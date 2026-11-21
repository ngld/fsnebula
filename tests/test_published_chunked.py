"""Tests for one fix: multiupload/finish leaves the record of a permanent file
alone.

    python tests/test_published_chunked.py

See tests/common.py for what is needed to run them.
"""
import os
import unittest

from common import (
    PublishedFile, UPLOADS, create_mod, finish, make_user, models, release, send_chunks, sha,
    upload_chunked, upload_small
)


class ChunkedFinishOfPermanentFile(PublishedFile):
    def test_other_bytes_under_a_published_checksum(self):
        headers = make_user('carol')
        other = make_user('dave')
        data = b'published archive bytes'
        self.publish(headers, data)
        resp = upload_chunked(other, '12' * 8, b'something else entirely', sha(data))
        self.assert_still_published(data)
        self.assertEqual(resp.get_json(), {'result': False, 'reason': 'checksum fail'})

    def test_same_bytes_under_a_published_checksum(self):
        headers = make_user('carol')
        data = b'published archive bytes'
        self.publish(headers, data)
        resp = upload_chunked(headers, '34' * 8, data, sha(data))
        self.assert_still_published(data)
        self.assertEqual(resp.get_json(), {'result': True})

    def test_same_bytes_again_finish_the_upload_and_remove_its_chunks(self):
        headers = make_user('carol')
        data = b'published archive bytes'
        self.publish(headers, data)
        models.UploadedFile.objects(checksum=sha(data)).update_one(set__indexed=True)
        before = os.stat(os.path.join(UPLOADS, models.UploadedFile.objects(checksum=sha(data)).first().filename))
        upload_chunked(headers, '56' * 8, data, sha(data))
        self.assertFalse(os.path.exists(os.path.join(UPLOADS, 'chunks', '56' * 8)))
        self.assertTrue(models.ChunkedUpload.objects(id='56' * 8).first().done)
        # Neither the record nor the file is written a second time.
        record = models.UploadedFile.objects(checksum=sha(data)).first()
        self.assertTrue(record.indexed)
        self.assertEqual(os.stat(os.path.join(UPLOADS, record.filename)).st_ino, before.st_ino)

    def test_finish_sent_twice(self):
        # With PR 49 in the tree its "if file.done" return answers the second
        # finish before the permanent-record check is reached. Kept to show
        # the record is still there and still permanent afterwards.
        headers = make_user('carol')
        data = b'chunked archive bytes'
        first = upload_chunked(headers, '78' * 8, data, sha(data))
        self.assertEqual(first.get_json(), {'result': True})
        second = finish(headers, '78' * 8, sha(data))
        record = models.UploadedFile.objects(checksum=sha(data)).first()
        self.assertIsNotNone(record)
        self.assertEqual(record.expires, -1)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.get_json(), {'result': True})

    def test_unreleased_file_finished_again_becomes_permanent(self):
        # Only permanent records are left alone: a temporary one is still
        # replaced by a finish whose chunks check out.
        headers = make_user('carol')
        data = b'not released yet'
        upload_small(headers, data)
        self.assertNotEqual(models.UploadedFile.objects(checksum=sha(data)).first().expires, -1)
        resp = upload_chunked(headers, '9a' * 8, data, sha(data))
        self.assertEqual(resp.get_json(), {'result': True})
        record = models.UploadedFile.objects(checksum=sha(data)).first()
        self.assertEqual(record.expires, -1)
        with open(os.path.join(UPLOADS, record.filename), 'rb') as stream:
            self.assertEqual(stream.read(), data)
        create_mod(headers, 'latemod')
        self.assertTrue(release(headers, 'latemod', '1.0.0', sha(data)).get_json()['result'])

    def test_published_file_missing_from_disk_is_not_restored(self):
        # A known cost, not a goal: the record is all that is looked at. The
        # chunks are joined and checked, then removed with the upload marked
        # done, and the file is still missing. Change this test with the
        # behaviour.
        headers = make_user('carol')
        data = b'published archive bytes'
        self.publish(headers, data)
        record = models.UploadedFile.objects(checksum=sha(data)).first()
        os.unlink(os.path.join(UPLOADS, record.filename))
        send_chunks(headers, 'bc' * 8, data)
        resp = finish(headers, 'bc' * 8, sha(data))
        self.assertEqual(resp.get_json(), {'result': True})
        self.assertFalse(os.path.exists(os.path.join(UPLOADS, record.filename)))
        self.assertTrue(models.ChunkedUpload.objects(id='bc' * 8).first().done)
        self.assertFalse(os.path.exists(os.path.join(UPLOADS, 'chunks', 'bc' * 8)))


if __name__ == '__main__':
    unittest.main(verbosity=2)
