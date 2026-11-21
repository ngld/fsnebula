"""Tests for one change: multiupload/finish joins the chunks under a name of
its own and saves nothing until the joined bytes match the checksum.

    python tests/test_finish_join.py

See tests/common.py for what is needed to run them.
"""
import builtins
import io
import logging
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
    return {name for name in stored_tree() if os.path.basename(name).startswith('joined-')}


def published(checksum):
    return '/'.join(('public', checksum[:2], checksum[2:4], checksum[4:]))


class OverlappingFinish(Base):
    """Two finish requests for one upload at the same time, which is what a
    client sends when the first one outlasts its timeout. Each request runs in
    a thread named A or B and is held at one chosen point until released.

    These need Linux or macOS file behaviour: they delete and rename open
    files, and rely on a rename giving the file a new inode."""

    def overlap(self, stop_at, start_order, release_order, before_release=None):
        """stop_at maps a thread name to where it waits: ('chunk', '2') just
        before it reads that chunk, ('move',) just before the joined file is
        moved into public/, ('rmtree',) just before the chunk folder is
        removed. `before_release`, if given, is called with the uploaded
        bytes once both requests are waiting."""
        headers = make_user('erin')
        parts = [bytes([65 + num]) * PART for num in range(4)]
        data = b''.join(parts)
        upload_id = 'ab' * 8
        send_parts(headers, upload_id, parts)
        chunk_dir = os.path.join(UPLOADS, 'chunks', upload_id)
        stopped = {name: threading.Event() for name in stop_at}
        carry_on = {name: threading.Event() for name in stop_at}

        def stop_here(*point):
            name = threading.current_thread().name
            if stop_at.get(name) == point:
                stopped[name].set()
                carry_on[name].wait(timeout=20)

        def stopping_open(path, mode='r', *args, **kwargs):
            if 'r' in mode and os.path.dirname(str(path)) == chunk_dir:
                stop_here('chunk', os.path.basename(str(path)))
            return builtins.open(path, mode, *args, **kwargs)

        real_move, real_rmtree = shutil.move, shutil.rmtree

        def stopping_move(*args, **kwargs):
            stop_here('move')
            return real_move(*args, **kwargs)

        def stopping_rmtree(*args, **kwargs):
            stop_here('rmtree')
            return real_rmtree(*args, **kwargs)

        answers = {}

        def call(label):
            resp = app.test_client().post('/api/1/multiupload/finish', headers=headers,
                                          data={'id': upload_id, 'checksum': sha(data)})
            answers[label] = (resp.status_code, resp.get_json(silent=True))

        upload_ctl.open = stopping_open
        self.addCleanup(delattr, upload_ctl, 'open')
        for name, stand_in in (('move', stopping_move), ('rmtree', stopping_rmtree)):
            patcher = mock.patch.object(shutil, name, stand_in)
            patcher.start()
            self.addCleanup(patcher.stop)
        # Whatever happens, let both threads run on, so a failed assert here
        # does not leave one waiting into the next test.
        for name in stop_at:
            self.addCleanup(carry_on[name].set)

        threads = {label: threading.Thread(target=call, args=(label,), name=label, daemon=True)
                   for label in start_order}
        for label in start_order:
            self.addCleanup(threads[label].join, 25)

        # Every error the app logs while the two requests run, in order. A
        # plain list and not assertLogs, which fails when nothing is logged.
        errors = []
        collector = logging.Handler(logging.ERROR)
        collector.emit = lambda record: errors.append(record.getMessage())
        level = app.logger.level
        app.logger.addHandler(collector)
        app.logger.setLevel(logging.ERROR)
        self.addCleanup(app.logger.setLevel, level)
        self.addCleanup(app.logger.removeHandler, collector)

        for label in start_order:
            threads[label].start()
            self.assertTrue(stopped[label].wait(timeout=20), 'request %s never reached its stop' % label)
        if before_release:
            before_release(data)
        for label in release_order:
            carry_on[label].set()
            threads[label].join(timeout=30)
            self.assertFalse(threads[label].is_alive())

        record = models.UploadedFile.objects(checksum=sha(data)).first()
        self.assertIsNotNone(record)
        self.assertEqual(record.expires, -1)
        self.assertEqual(record.filename, published(sha(data)))
        with open(os.path.join(UPLOADS, record.filename), 'rb') as stream:
            self.assertEqual(stream.read(), data)
        self.assertEqual(finish(headers, upload_id, sha(data)).get_json(), {'result': True})
        self.assertEqual(joined_leftovers(), set())
        self.assertNotIn(os.path.join('temp', sha(data)), stored_tree())
        return answers, errors, data

    def assert_errors_logged(self, errors, *starts):
        self.assertEqual(len(errors), len(starts), errors)
        for text, start in zip(errors, starts):
            self.assertTrue(text.startswith(start), text)

    def test_first_request_finishes_first(self):
        answers, errors, _ = self.overlap({'A': ('chunk', '2'), 'B': ('chunk', '0')}, 'AB', 'AB')
        self.assertEqual(answers['A'], (200, {'result': True}))
        # Not "checksum fail", which the client treats as final.
        self.assertEqual(answers['B'][0], 500)
        # One logged join failure and nothing uncaught: the loser's own
        # clean-up copes with its joined file having gone with the folder.
        self.assert_errors_logged(errors, 'Failed to join chunks')

    def test_second_request_finishes_first(self):
        answers, errors, _ = self.overlap({'A': ('chunk', '2'), 'B': ('chunk', '0')}, 'AB', 'BA')
        self.assertEqual(answers['B'], (200, {'result': True}))
        self.assertEqual(answers['A'][0], 500)
        self.assert_errors_logged(errors, 'Failed to join chunks')

    def test_loser_has_joined_everything_when_the_winner_finishes(self):
        # B is about to move its joined file when A publishes and removes the
        # chunk folder. B's move then has nothing to move; it must not empty
        # the file A published. (This rests on the library's move reading its
        # source first, so it passes on the old code too.)
        answers, errors, _ = self.overlap({'A': ('chunk', '2'), 'B': ('move',)}, 'AB', 'AB')
        self.assertEqual(answers['A'], (200, {'result': True}))
        self.assertEqual(answers['B'][0], 500)
        self.assert_errors_logged(errors, 'Exception on /api/1/multiupload/finish')

    def test_both_requests_join_everything(self):
        # A has published and is about to remove the chunk folder; B, which
        # started before A was done, then joins the same chunks. B must see
        # A's record and leave the published file as it is: the same file on
        # disk, not a second copy moved over it.
        noted = {}

        def note_file(data):
            noted['inode'] = os.stat(os.path.join(UPLOADS, published(sha(data)))).st_ino

        answers, errors, data = self.overlap({'B': ('chunk', '0'), 'A': ('rmtree',)}, 'BA', 'BA',
                                             before_release=note_file)
        self.assertEqual(answers, {'A': (200, {'result': True}), 'B': (200, {'result': True})})
        self.assertEqual(os.stat(os.path.join(UPLOADS, published(sha(data)))).st_ino, noted['inode'])
        # A finds the folder already removed by B.
        self.assert_errors_logged(errors, 'Failed to cleanup chunk directory')

    def test_known_cost_both_requests_are_past_the_look_up(self):
        # A known cost, not a goal: the look-up and the publish are two
        # steps. B has looked (nothing published yet) and is about to move
        # when A publishes; B then publishes the same checked bytes over A's
        # file and saves the record again, resetting its other fields.
        # Change this test with the behaviour.
        noted = {}

        def note_file(data):
            noted['inode'] = os.stat(os.path.join(UPLOADS, published(sha(data)))).st_ino
            models.UploadedFile.objects(checksum=sha(data)).update_one(set__indexed=True)

        answers, errors, data = self.overlap({'B': ('move',), 'A': ('rmtree',)}, 'BA', 'BA',
                                             before_release=note_file)
        self.assertEqual(answers, {'A': (200, {'result': True}), 'B': (200, {'result': True})})
        self.assertNotEqual(os.stat(os.path.join(UPLOADS, published(sha(data)))).st_ino, noted['inode'])
        self.assertFalse(models.UploadedFile.objects(checksum=sha(data)).first().indexed)
        self.assert_errors_logged(errors, 'Failed to cleanup chunk directory')


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
        self.assertEqual(finish(other, 'ce' * 8, sha(data)).status_code, 500)
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
        self.assertEqual(finish(headers, '23' * 8, sha(data)).status_code, 500)
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

    def test_joined_file_left_by_a_stopped_request_goes_with_the_next_finish(self):
        # A known cost: a request stopped without its clean-up running (a
        # killed worker) leaves its joined file. It is in the upload's own
        # folder, so the next finish that succeeds removes it.
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
        self.assertEqual(len(joined_leftovers()), 1)
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
        self.assertEqual(finish(headers, '8b' * 8, sha(b'whatever')).status_code, 500)
        self.assertFalse(os.path.exists(old))
        self.assertTrue(os.path.exists(recent))

    def test_a_part_cannot_be_given_the_joined_file_name(self):
        headers = make_user('carol')
        send_parts(headers, '67' * 8, [b'part'])
        resp = client.post('/api/1/multiupload/part', headers=headers,
                           data={'id': '67' * 8, 'part': 'joined-00', 'file': (io.BytesIO(b'x'), 'p')},
                           content_type='multipart/form-data')
        self.assertEqual(resp.status_code, 500)
        self.assertEqual(joined_leftovers(), set())


if __name__ == '__main__':
    unittest.main(verbosity=2)
