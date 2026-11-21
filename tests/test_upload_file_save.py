"""Tests for one change: upload/file saves its temporary record in one database
step that leaves a permanent record alone.

    python tests/test_upload_file_save.py

See tests/common.py for what is needed to run them.
"""
import io
import os
import time
import unittest
from unittest import mock

from common import (
    Base, PublishedFile, UPLOADS, client, make_user, models, sha, stored_tree, upload_chunked,
    upload_small
)
from app.controllers import upload as upload_ctl
from mongoengine.errors import ValidationError
from pymongo.errors import DuplicateKeyError, OperationFailure


def temporary(checksum, expires):
    record = models.UploadedFile(checksum=checksum, expires=expires, filesize=3)
    record.gen_filename()
    return record


class SaveUnlessPermanent(Base):
    def test_no_record_yet(self):
        self.assertTrue(temporary('aa' * 32, 100).save_unless_permanent())
        stored = models.UploadedFile.objects(checksum='aa' * 32).first()
        self.assertEqual((stored.expires, stored.filename), (100, 'temp/' + 'aa' * 32))

    def test_temporary_record_is_replaced(self):
        temporary('aa' * 32, 100).save()
        self.assertTrue(temporary('aa' * 32, 200).save_unless_permanent())
        self.assertEqual(models.UploadedFile.objects(checksum='aa' * 32).first().expires, 200)
        self.assertEqual(models.UploadedFile.objects.count(), 1)

    def test_permanent_record_is_left_alone(self):
        models.UploadedFile(checksum='bb' * 32, expires=-1, filesize=3, filename='public/bb/bb/rest').save()
        self.assertFalse(temporary('bb' * 32, 300).save_unless_permanent())
        stored = models.UploadedFile.objects(checksum='bb' * 32).first()
        self.assertEqual((stored.expires, stored.filename), (-1, 'public/bb/bb/rest'))

    def refusing(self, refusals):
        """Stands in for the collection: its first `refusals` saves are
        refused the way the database refuses an insert whose checksum is
        already there; later ones go through. Returns the list of calls and
        the real collection, for reading back what was stored."""
        real = models.UploadedFile._get_collection()
        calls = []

        def replace_one(*args, **kwargs):
            calls.append(args)
            if len(calls) <= refusals:
                raise DuplicateKeyError('refused by the test')
            return real.replace_one(*args, **kwargs)

        patcher = mock.patch.object(models.UploadedFile, '_get_collection',
                                    return_value=mock.Mock(replace_one=replace_one))
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls, real

    def test_one_refusal_is_tried_again(self):
        # Two first saves of one new checksum at the same moment: the one
        # the database refuses finds the other's record on its second try.
        calls, stored = self.refusing(1)
        self.assertTrue(temporary('dd' * 32, 100).save_unless_permanent())
        self.assertEqual(len(calls), 2)
        self.assertEqual(stored.find_one({'_id': 'dd' * 32})['expires'], 100)

    def test_two_refusals_end_the_tries(self):
        # Only the count is staged here; a real permanent record refusing
        # the save is test_permanent_record_is_left_alone.
        calls, stored = self.refusing(2)
        self.assertFalse(temporary('dd' * 32, 100).save_unless_permanent())
        self.assertEqual(len(calls), 2)
        self.assertIsNone(stored.find_one({'_id': 'dd' * 32}))

    def test_other_database_errors_are_not_swallowed(self):
        real = models.UploadedFile._get_collection()
        failing = mock.Mock(replace_one=mock.Mock(side_effect=OperationFailure('not a refusal')))
        with mock.patch.object(models.UploadedFile, '_get_collection', return_value=failing):
            with self.assertRaises(OperationFailure):
                temporary('ee' * 32, 100).save_unless_permanent()
        self.assertEqual(failing.replace_one.call_count, 1)
        self.assertIsNone(real.find_one({'_id': 'ee' * 32}))

    def test_record_is_checked_like_a_normal_save(self):
        record = models.UploadedFile(checksum='cc' * 32, expires=100)
        with self.assertRaises(ValidationError):
            record.save_unless_permanent()
        self.assertIsNone(models.UploadedFile.objects(checksum='cc' * 32).first())


class ReleaseLandsDuringUpload(PublishedFile):
    def test_file_made_permanent_just_before_the_save(self):
        headers = make_user('carol')
        data = b'sent twice, released in between'
        upload_small(headers, data)
        landed = []

        class ReleaseLands:
            # Stands in for a release request that makes the file permanent
            # after any look-up, just before upload/file writes its record.
            def __init__(self, collection):
                self.collection = collection

            def __getattr__(self, name):
                attr = getattr(self.collection, name)
                if name == 'with_options':
                    return lambda *args, **kwargs: ReleaseLands(attr(*args, **kwargs))
                if name not in ('replace_one', 'find_one_and_replace', 'insert_one', 'update_one') or landed:
                    return attr

                def write(*args, **kwargs):
                    landed.append(name)
                    models.UploadedFile.objects(checksum=sha(data)).first().make_permanent()
                    return attr(*args, **kwargs)
                return write

        stand_in = ReleaseLands(models.UploadedFile._get_collection())
        with mock.patch.object(models.UploadedFile, '_get_collection', return_value=stand_in):
            resp = upload_small(headers, data)
        self.assertTrue(landed)
        self.assertEqual(resp.get_json(), {'result': True})
        record = models.UploadedFile.objects(checksum=sha(data)).first()
        self.assertEqual(record.expires, -1)
        with open(os.path.join(UPLOADS, record.filename), 'rb') as stream:
            self.assertEqual(stream.read(), data)
        self.assertNotIn(os.path.join('temp', sha(data)), stored_tree())

    def test_published_file_sent_again(self):
        headers = make_user('carol')
        data = b'published archive bytes'
        self.publish(headers, data)
        self.assertEqual(upload_small(headers, data).get_json(), {'result': True})
        self.assert_still_published(data)
        self.assertNotIn(os.path.join('temp', sha(data)), stored_tree())

    def test_blocked_type_is_refused_even_when_the_server_has_the_file(self):
        # The chunked route has no type check, so a blocked type can be
        # permanent. The type check here runs before the save, as it did
        # before the permanent look-up was added and removed again.
        headers = make_user('carol')
        data = b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00' + b'\x00' * 112
        self.assertEqual(upload_ctl.magic.from_buffer(data, mime=True), 'application/x-dosexec')
        self.assertEqual(upload_chunked(headers, '89' * 8, data, sha(data)).get_json(), {'result': True})
        resp = upload_small(headers, data)
        self.assertEqual(resp.get_json(), {'result': False, 'reason': 'invalid mime'})
        self.assertEqual(models.UploadedFile.objects(checksum=sha(data)).first().expires, -1)

    def test_field_the_model_refuses_is_an_error_even_when_the_server_has_the_file(self):
        # Like the blocked type above: the record is checked before the save,
        # as it was before the permanent look-up was added and removed again.
        headers = make_user('carol')
        data = b'published archive bytes'
        self.publish(headers, data)
        resp = client.post('/api/1/upload/file', headers=headers,
                           data={'checksum': sha(data), 'content_checksum': 'c' * 129,
                                 'file': (io.BytesIO(data), 'f.bin')},
                           content_type='multipart/form-data')
        self.assertEqual(resp.status_code, 500)
        self.assert_still_published(data)

    def test_unreleased_file_sent_again_stays_usable(self):
        headers = make_user('carol')
        data = b'not released yet'
        upload_small(headers, data)
        before = models.UploadedFile.objects(checksum=sha(data)).first().expires
        self.assertEqual(upload_small(headers, data).get_json(), {'result': True})
        record = models.UploadedFile.objects(checksum=sha(data)).first()
        self.assertGreaterEqual(record.expires, before)
        self.assertGreater(record.expires, time.time())
        with open(os.path.join(UPLOADS, record.filename), 'rb') as stream:
            self.assertEqual(stream.read(), data)


if __name__ == '__main__':
    unittest.main(verbosity=2)
