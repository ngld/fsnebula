"""Tests for one change: multiupload/finish joins the chunks under a name of
its own and saves nothing until the joined bytes match the checksum.

    python tests/test_finish_join.py

See tests/common.py for what is needed to run them.
"""
import builtins
import io
import os
import shutil
import threading
import time
import unittest
from unittest import mock

from common import (
    Base, UPLOADS, app, client, create_mod, finish, make_user, models, release, sha, stored_tree,
    upload_small
)
from app.controllers import upload as upload_ctl

# Larger than Python's 8 KB file buffer, so each part reaches the disk when it
# is written and not only when the file is closed.
PART = 64 * 1024


def send_parts(headers, upload_id, parts, announced=None):
    resp = client.post('/api/1/multiupload/start', headers=headers,
                       data={'id': upload_id, 'size': str(sum(len(part) for part in parts)),
                             'parts': str(announced or len(parts))})
    assert resp.status_code == 200, resp.status_code
    for num, part in enumerate(parts):
        resp = client.post('/api/1/multiupload/part', headers=headers,
                           data={'id': upload_id, 'part': str(num), 'file': (io.BytesIO(part), 'p')},
                           content_type='multipart/form-data')
        assert resp.status_code == 200, resp.status_code


def joined_leftovers():
    return {name for name in stored_tree() if os.path.basename(name).startswith(('joined-', 'assembly-'))}


def published(checksum):
    return '/'.join(('public', checksum[:2], checksum[2:4], checksum[4:]))


class OverlappingFinish(Base):
    def assert_serialized_finish(self, retry_id):
        headers = make_user('erin')
        parts = [bytes([65 + num]) * PART for num in range(4)]
        data = b''.join(parts)
        checksum = sha(data)
        upload_id = 'ab' * 8
        send_parts(headers, upload_id, parts)
        if retry_id != upload_id:
            send_parts(headers, retry_id, parts)

        assembling = threading.Event()
        resume = threading.Event()
        assemble = upload_ctl._assemble_upload
        answers = []

        def pause(*args, **kwargs):
            assembling.set()
            if not resume.wait(timeout=15):
                raise RuntimeError('Timed out waiting to resume assembly')
            return assemble(*args, **kwargs)

        def call_finish():
            answers.append(app.test_client().post(
                '/api/1/multiupload/finish', headers=headers, data={'id': upload_id, 'checksum': checksum}))

        with mock.patch.object(upload_ctl, '_assemble_upload', pause):
            worker = threading.Thread(target=call_finish, daemon=True)
            worker.start()
            try:
                self.assertTrue(assembling.wait(timeout=10))
                retry = finish(headers, retry_id, checksum)
                self.assertEqual(retry.status_code, 503)
                self.assertEqual(retry.get_json(), {'result': False, 'reason': 'upload busy'})
                self.assertIsNone(models.UploadedFile.objects(checksum=checksum).first())
                self.assertNotIn(os.path.normpath(published(checksum)), stored_tree())
            finally:
                resume.set()
                worker.join(timeout=20)

        self.assertFalse(worker.is_alive())
        self.assertEqual([response.get_json() for response in answers], [{'result': True}])
        record = models.UploadedFile.objects.get(checksum=checksum)
        self.assertEqual(record.expires, -1)
        self.assertEqual(record.filename, published(checksum))
        path = os.path.join(UPLOADS, record.filename)
        inode = os.stat(path).st_ino
        record.update(set__indexed=True)

        self.assertEqual(finish(headers, retry_id, checksum).get_json(), {'result': True})
        self.assertTrue(models.ChunkedUpload.objects.get(id=retry_id).done)
        self.assertEqual(os.stat(path).st_ino, inode)
        self.assertTrue(models.UploadedFile.objects.get(checksum=checksum).indexed)
        with open(path, 'rb') as stream:
            self.assertEqual(stream.read(), data)
        self.assertEqual(joined_leftovers(), set())
        self.assertNotIn(os.path.join('chunks', retry_id), stored_tree())

    def test_retry_for_the_same_upload_is_busy_until_the_first_finishes(self):
        self.assert_serialized_finish('ab' * 8)

    def test_two_upload_ids_for_the_same_checksum_publish_once(self):
        self.assert_serialized_finish('bc' * 8)


class FinishSavesNothingEarly(Base):
    def test_wrong_bytes_leave_an_unreleased_file_alone(self):
        owner = make_user('carol')
        other = make_user('dave')
        data = b'not released yet'
        upload_small(owner, data)
        send_parts(other, 'cd' * 8, [b'something else entirely'])
        resp = finish(other, 'cd' * 8, sha(data))
        self.assertEqual(resp.get_json(), {'result': False, 'reason': 'checksum fail'})
        self.assert_unreleased_file_intact(owner, data)

    def test_failed_join_leaves_an_unreleased_file_alone(self):
        owner = make_user('carol')
        other = make_user('dave')
        data = b'not released yet'
        upload_small(owner, data)
        send_parts(other, 'ce' * 8, [b'first of two parts'], announced=2)
        self.assertEqual(finish(other, 'ce' * 8, sha(data)).get_json(),
                         {'result': False, 'reason': 'part missing'})
        self.assert_unreleased_file_intact(owner, data)

    def assert_unreleased_file_intact(self, owner, data):
        record = models.UploadedFile.objects(checksum=sha(data)).first()
        self.assertIsNotNone(record)
        with open(os.path.join(UPLOADS, record.filename), 'rb') as stream:
            self.assertEqual(stream.read(), data)
        self.assertEqual(joined_leftovers(), set())
        create_mod(owner, 'latemod')
        self.assertTrue(release(owner, 'latemod', '1.0.0', sha(data)).get_json()['result'])

    def test_nothing_is_saved_while_the_chunks_are_joined(self):
        headers = make_user('carol')
        data = b'chunked archive bytes'
        send_parts(headers, 'ef' * 8, [data])
        chunk_dir = os.path.join(UPLOADS, 'chunks', 'ef' * 8)
        seen = {}

        def looking_open(path, mode='r', *args, **kwargs):
            if 'r' in mode and os.path.dirname(str(path)) == chunk_dir:
                seen['record'] = models.UploadedFile.objects(checksum=sha(data)).first()
                seen['temp file'] = os.path.join('temp', sha(data)) in stored_tree()
            return builtins.open(path, mode, *args, **kwargs)

        upload_ctl.open = looking_open
        self.addCleanup(delattr, upload_ctl, 'open')
        self.assertEqual(finish(headers, 'ef' * 8, sha(data)).get_json(), {'result': True})
        self.assertEqual(seen, {'record': None, 'temp file': False})

    def test_right_bytes_are_published_and_the_chunks_removed(self):
        headers = make_user('carol')
        parts = [b'first part ', b'second part']
        data = b''.join(parts)
        send_parts(headers, '01' * 8, parts)
        self.assertEqual(finish(headers, '01' * 8, sha(data)).get_json(), {'result': True})
        record = models.UploadedFile.objects(checksum=sha(data)).first()
        self.assertEqual(record.expires, -1)
        self.assertEqual(record.filename, published(sha(data)))
        with open(os.path.join(UPLOADS, record.filename), 'rb') as stream:
            self.assertEqual(stream.read(), data)
        self.assertTrue(models.ChunkedUpload.objects(id='01' * 8).first().done)
        self.assertNotIn(os.path.join('chunks', '01' * 8), stored_tree())
        self.assertNotIn(os.path.join('temp', sha(data)), stored_tree())

    def test_a_missing_chunk_leaves_no_record_and_no_joined_file(self):
        headers = make_user('carol')
        data = b'only the first of two parts'
        send_parts(headers, '23' * 8, [data], announced=2)
        self.assertEqual(finish(headers, '23' * 8, sha(data)).get_json(),
                         {'result': False, 'reason': 'part missing'})
        self.assertIsNone(models.UploadedFile.objects(checksum=sha(data)).first())
        self.assertEqual(joined_leftovers(), set())
        self.assertFalse(models.ChunkedUpload.objects(id='23' * 8).first().done)

    def test_wrong_bytes_leave_no_record_and_no_joined_file(self):
        headers = make_user('carol')
        send_parts(headers, '45' * 8, [b'these bytes'])
        resp = finish(headers, '45' * 8, sha(b'other bytes'))
        self.assertEqual(resp.get_json(), {'result': False, 'reason': 'checksum fail'})
        self.assertIsNone(models.UploadedFile.objects(checksum=sha(b'other bytes')).first())
        self.assertEqual(joined_leftovers(), set())

    def test_a_field_the_model_refuses_stops_the_request_before_anything_is_published(self):
        headers = make_user('carol')
        data = b'right bytes, over-long optional field'
        for field in ('content_checksum', 'vp_checksum'):
            with self.subTest(field=field):
                models.ChunkedUpload.drop_collection()
                shutil.rmtree(os.path.join(UPLOADS, 'chunks', '9b' * 8), ignore_errors=True)
                send_parts(headers, '9b' * 8, [data])
                resp = client.post('/api/1/multiupload/finish', headers=headers,
                                   data={'id': '9b' * 8, 'checksum': sha(data), field: 'c' * 129})
                self.assertEqual(resp.status_code, 500)
                self.assertNotIn(os.path.normpath(published(sha(data))), stored_tree())
                self.assertIsNone(models.UploadedFile.objects(checksum=sha(data)).first())
                self.assertEqual(joined_leftovers(), set())
                self.assertFalse(models.ChunkedUpload.objects(id='9b' * 8).first().done)

    def test_interrupted_join_and_retry_clean_up_their_own_files(self):
        class Stopped(BaseException):
            pass

        headers = make_user('carol')
        data = b'chunked archive bytes'
        send_parts(headers, '8a' * 8, [data])
        chunk_dir = os.path.join(UPLOADS, 'chunks', '8a' * 8)

        def stopping_open(path, mode='r', *args, **kwargs):
            if 'r' in mode and os.path.dirname(str(path)) == chunk_dir:
                raise Stopped()
            return builtins.open(path, mode, *args, **kwargs)

        upload_ctl.open = stopping_open
        try:
            with self.assertRaises(Stopped):
                finish(headers, '8a' * 8, sha(data))
        finally:
            del upload_ctl.open
        self.assertEqual(joined_leftovers(), set())
        # A process kill can bypass the temporary directory's cleanup.
        stale = os.path.join(chunk_dir, 'assembly-interrupted')
        os.makedirs(stale)
        self.assertEqual(finish(headers, '8a' * 8, sha(data)).get_json(), {'result': True})
        self.assertEqual(joined_leftovers(), set())

    def test_old_joined_files_are_removed_before_joining(self):
        headers = make_user('carol')
        send_parts(headers, '8b' * 8, [b'first of two parts'], announced=2)
        chunk_dir = os.path.join(UPLOADS, 'chunks', '8b' * 8)
        self.addCleanup(shutil.rmtree, chunk_dir, ignore_errors=True)
        old, recent = os.path.join(chunk_dir, 'joined-old'), os.path.join(chunk_dir, 'joined-recent')
        for path in (old, recent):
            with open(path, 'wb') as stream:
                stream.write(b'left by a killed request')
        hour_ago = time.time() - 60 * 60 - 60
        os.utime(old, (hour_ago, hour_ago))
        # The missing part makes this finish fail, so the folder stays.
        self.assertEqual(finish(headers, '8b' * 8, sha(b'whatever')).get_json(),
                         {'result': False, 'reason': 'part missing'})
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(recent))

    def test_a_part_cannot_be_given_the_joined_file_name(self):
        headers = make_user('carol')
        send_parts(headers, '67' * 8, [b'part'])
        resp = client.post('/api/1/multiupload/part', headers=headers,
                           data={'id': '67' * 8, 'part': 'joined-00', 'file': (io.BytesIO(b'x'), 'p')},
                           content_type='multipart/form-data')
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(joined_leftovers(), set())


if __name__ == '__main__':
    unittest.main(verbosity=2)
