"""API V1 regression tests. Set NEBULA_TEST_MONGO_HOST to an isolated MongoDB."""

import builtins
import hashlib
import io
import multiprocessing
import os
import shutil
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import requests
from mongoengine import disconnect
from werkzeug.serving import make_server
from werkzeug.test import EnvironBuilder


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def serve_upload(pipe, role, public_path, first_chunk, blocked, overlap, proceed, legacy):
    from app import app
    from app.models import UploadedFile

    real_open = builtins.open
    real_replace = os.replace
    real_publish = UploadedFile.make_permanent
    real_save = UploadedFile.save

    def pause():
        blocked.set()
        if not proceed.wait(25):
            raise RuntimeError('Timed out waiting to resume upload')

    def publish(record):
        if legacy and role == 'first':
            pause()
        return real_publish(record)

    def replace(source, dest):
        if role == 'first' and Path(dest) == public_path:
            pause()
        return real_replace(source, dest)

    def save(record, *args, **kwargs):
        if role == 'crash' and record.expires == -1 and public_path.exists():
            os._exit(17)
        return real_save(record, *args, **kwargs)

    def open_file(path, mode='r', *args, **kwargs):
        stream = real_open(path, mode, *args, **kwargs)
        if legacy and role == 'second' and mode == 'rb' and path == str(first_chunk):
            overlap.set()
            if not proceed.wait(25):
                stream.close()
                raise RuntimeError('Timed out waiting to resume second upload')
        return stream

    with patch.object(UploadedFile, 'make_permanent', publish), \
            patch.object(UploadedFile, 'save', save), \
            patch.object(os, 'replace', replace), patch('builtins.open', open_file):
        with make_server('127.0.0.1', 0, app, threaded=True) as server:
            pipe.send(server.server_port)
            pipe.close()
            server.serve_forever()


class MultipartUploadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.TemporaryDirectory()
        root = Path(cls.work_dir.name)
        cls.storage = root / 'uploads'
        cls.db_name = 'nebula_upload_test_' + uuid.uuid4().hex
        mongo = os.environ.get('NEBULA_TEST_MONGO_HOST', '127.0.0.1:27017')
        cfg = root / 'test.cfg'
        cfg.write_text(Path(__file__).resolve().parents[1].joinpath('dev.cfg').read_text() +
                       '\nMONGO_DB = %r\nFILE_STORAGE = %r\nJWT_SECRET = %r\n' %
                       ('mongodb://%s/%s' % (mongo, cls.db_name), str(cls.storage), os.urandom(64)))
        cls.env = patch.dict(os.environ, {'NEBULA_SETTINGS': str(cfg)})
        cls.env.start()

        from app import app
        from app.models import User
        from app.helpers import generate_token
        from mongoengine.connection import get_connection

        cls.mongo = get_connection()
        cls.mongo.admin.command('ping')
        cls.client = app.test_client()
        cls.user = User(username='upload-test', active=True, email='test@example.invalid',
                        password='unused').save()
        cls.headers = {'X-KN-TOKEN': generate_token(cls.user.username)}

    @classmethod
    def tearDownClass(cls):
        cls.mongo.drop_database(cls.db_name)
        disconnect()
        cls.env.stop()
        cls.work_dir.cleanup()

    def setUp(self):
        from app.models import ChunkedUpload, UploadedFile, ModRelease

        ChunkedUpload.objects.delete()
        UploadedFile.objects.delete()
        ModRelease.objects.delete()
        if self.storage.exists():
            shutil.rmtree(str(self.storage))

        part_size = int(os.environ.get('NEBULA_TEST_PART_BYTES', str(64 * 1024)))
        part_count = int(os.environ.get('NEBULA_TEST_PART_COUNT', '3'))
        samples = [char * part_size for char in (b'a', b'b', b'c')]
        self.parts = [samples[i % len(samples)] for i in range(part_count)]
        digest = hashlib.sha256()
        for part in self.parts:
            digest.update(part)
        self.size = sum(map(len, self.parts))
        self.checksum = digest.hexdigest()
        self.chunk_dir = self.storage / 'chunks' / self.checksum
        self.public_path = self.storage / 'public' / self.checksum[:2] / self.checksum[2:4] / self.checksum[4:]
        self.start_data = {'id': self.checksum, 'size': self.size, 'parts': len(self.parts)}
        self.finish_data = {'id': self.checksum, 'checksum': self.checksum,
                            'content_checksum': 'None', 'vp_checksum': 'None'}
        self.processes = multiprocessing.get_context('spawn')

    def post(self, action, data):
        return self.client.post('/api/1/multiupload/' + action, data=data, headers=self.headers)

    def post_file(self, path, data):
        with closing(EnvironBuilder(path=path, method='POST', headers=self.headers, data=data)) as builder:
            environ = builder.get_environ()
            with environ['wsgi.input']:
                return self.client.open(environ)

    def put_part(self, number, data):
        response = self.post_file('/api/1/multiupload/part', {'id': self.checksum, 'part': number,
                                                             'file': (io.BytesIO(data), 'part')})
        self.assertEqual(response.data, b'OK')

    def verify_part(self, number, data):
        return self.post('verify_part', {'id': self.checksum, 'part': number, 'checksum': sha256(data)})

    def prepare(self):
        self.assertEqual(self.post('start', self.start_data).get_json(),
                         {'result': True, 'done': False, 'finished_parts': []})
        for i, part in enumerate(self.parts):
            self.put_part(i, part)
            self.assertEqual(self.verify_part(i, part).get_json(), {'result': True})

    def server(self, role='', blocked=None, overlap=None, proceed=None, legacy=False):
        receiver, sender = self.processes.Pipe(duplex=False)
        worker = self.processes.Process(
            target=serve_upload, args=(sender, role, self.public_path, self.chunk_dir / '0',
                                       blocked, overlap, proceed, legacy))
        worker.start()
        sender.close()

        def stop():
            if worker.is_alive():
                worker.terminate()
            worker.join(5)

        self.addCleanup(stop)
        with receiver:
            self.assertTrue(receiver.poll(15), 'Test worker failed to start')
            return 'http://127.0.0.1:%d/api/1/multiupload/' % receiver.recv(), worker

    def http(self, server, action, data):
        return requests.post(server + action, data=data, headers=self.headers, timeout=25)

    def assert_published(self):
        from app.helpers import gen_hash
        from app.models import ChunkedUpload, UploadedFile

        record = UploadedFile.objects.get(checksum=self.checksum)
        self.assertEqual(record.expires, -1)
        self.assertEqual(record.filesize, self.size)
        self.assertEqual(self.storage / record.filename, self.public_path)
        self.assertTrue(ChunkedUpload.objects.get(id=self.checksum).done)
        self.assertEqual(self.public_path.stat().st_size, self.size)
        with self.public_path.open('rb') as stream:
            self.assertEqual(gen_hash(stream, 'sha256'), self.checksum)
        self.assertFalse(self.chunk_dir.exists())

    def test_two_processes_retry_during_publication(self):
        from app.models import UploadedFile

        legacy = os.environ.get('NEBULA_TEST_EXPECT_RACE') == '1'
        self.prepare()
        first_blocked = self.processes.Event()
        second_blocked = self.processes.Event()
        continue_first = self.processes.Event()
        continue_second = self.processes.Event()
        first, _ = self.server('first', blocked=first_blocked, proceed=continue_first, legacy=legacy)
        second, _ = self.server('second', overlap=second_blocked, proceed=continue_second, legacy=legacy)

        with ThreadPoolExecutor(max_workers=2) as executor:
            try:
                pending = executor.submit(self.http, first, 'finish', self.finish_data)
                self.assertTrue(first_blocked.wait(15), 'First worker did not reach publication')
                retry = executor.submit(self.http, second, 'finish', self.finish_data)
                if legacy:
                    self.assertTrue(second_blocked.wait(15), 'Second worker failed to open the first chunk')
                else:
                    self.assertEqual(retry.result(5).status_code, 503)
                    poll = self.http(second, 'start', self.start_data)
                    self.assertEqual(poll.json(), {'result': True, 'done': False,
                                                   'finished_parts': list(range(len(self.parts)))})
                    self.assertIsNone(UploadedFile.objects(checksum=self.checksum).first())
                    self.assertFalse(self.public_path.exists())

                continue_first.set()
                self.assertEqual(pending.result(15).json(), {'result': True})
                continue_second.set()
                if legacy:
                    self.assertEqual(retry.result(15).status_code, 500)
                    received = self.public_path.read_bytes()
                    self.assertEqual(received, self.parts[0])
                    self.assertTrue(self.http(first, 'start', self.start_data).json()['done'])
                    self.assertIsNotNone(UploadedFile.objects(checksum=self.checksum).first())
                    print('Legacy: expected %s bytes %s, published %s bytes %s' %
                          (self.size, self.checksum, len(received), sha256(received)), flush=True)
                else:
                    self.assertTrue(self.http(second, 'start', self.start_data).json()['done'])
                    self.assertEqual(self.http(second, 'finish', self.finish_data).json(), {'result': True})
                    self.assert_published()
                    print('Fixed: published %s bytes %s' % (self.size, self.checksum), flush=True)
            finally:
                continue_first.set()
                continue_second.set()

    def test_recover_after_worker_exits_between_rename_and_save(self):
        from app.models import ChunkedUpload, UploadedFile

        self.prepare()
        server, worker = self.server('crash')
        with self.assertRaises(requests.ConnectionError):
            self.http(server, 'finish', self.finish_data)
        worker.join(10)
        self.assertEqual(worker.exitcode, 17)
        self.assertTrue(self.public_path.is_file())
        self.assertIsNone(UploadedFile.objects(checksum=self.checksum).first())
        self.assertFalse(ChunkedUpload.objects.get(id=self.checksum).done)

        response = self.post('finish', self.finish_data)
        self.assertEqual(response.get_json(), {'result': True})
        self.assert_published()

    def test_lost_legacy_record_recovered_only_if_bytes_match(self):
        from app.models import UploadedFile

        self.prepare()
        self.assertEqual(self.post('finish', self.finish_data).get_json(), {'result': True})
        UploadedFile.objects(checksum=self.checksum).delete()
        (self.storage / 'upload-locks' / self.checksum[:2] / self.checksum[2:]).write_bytes(b'')
        self.assertTrue(self.post('start', self.start_data).get_json()['done'])
        self.assert_published()

        self.public_path.write_bytes(b'x' * self.size)
        self.assertEqual(self.post('start', self.start_data).get_json(),
                         {'result': True, 'done': False, 'finished_parts': []})
        UploadedFile.objects(checksum=self.checksum).delete()
        self.assertFalse(self.post('start', self.start_data).get_json()['done'])
        self.assertIsNone(UploadedFile.objects(checksum=self.checksum).first())
        self.assertEqual(self.public_path.stat().st_size, self.size)

    def test_repair_truncated_object_and_reject_it_before_release(self):
        from app.models import Mod, ModRelease, TeamMember, TEAM_OWNER

        self.prepare()
        self.assertEqual(self.post('finish', self.finish_data).get_json(), {'result': True})
        self.public_path.write_bytes(self.parts[0])
        mod = Mod(mid='upload-test', title='Upload test', type='mod',
                  team=[TeamMember(user=self.user, role=TEAM_OWNER)]).save()
        release = {'id': mod.mid, 'version': '1.0.0', 'mod_flag': [], 'chunked_upload': True,
                   'chunks': ['core', 'optional'],
                   'packages': [{'name': 'core', 'filelist': [], 'files': [
                       {'filename': 'test.7z', 'dest': '', 'checksum': ['sha256', self.checksum],
                        'filesize': self.size}]}]}

        check = self.client.post('/api/1/upload/check', headers=self.headers, data={'checksum': self.checksum})
        self.assertEqual(check.get_json(), {'result': False})
        response = self.client.post('/api/1/mod/release', headers=self.headers, json=release)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {'result': False, 'reason': 'archive missing', 'archive': 'test.7z'})
        self.assertFalse(ModRelease.objects(mod=mod).first())

        self.prepare()
        self.assertEqual(self.post('finish', self.finish_data).get_json(), {'result': True})
        self.assert_published()
        response = self.client.post('/api/1/mod/release', headers=self.headers, json=release)
        self.assertEqual(response.get_json(), {'result': True})
        self.assertIsNotNone(ModRelease.objects(mod=mod).first())
        download = self.client.get('/storage/' + self.public_path.relative_to(self.storage / 'public').as_posix())
        self.assertEqual(download.status_code, 200)
        self.assertEqual(sha256(download.data), self.checksum)
        download.close()

    def test_missing_and_corrupt_parts_can_be_retried(self):
        self.prepare()
        self.assertTrue(self.verify_part(0, self.parts[0]).get_json()['result'])
        self.assertEqual(self.post('start', self.start_data).get_json()['finished_parts'], [0, 1, 2])
        (self.chunk_dir / '1').unlink()
        self.assertEqual(self.post('finish', self.finish_data).get_json(),
                         {'result': False, 'reason': 'part missing'})
        self.put_part(1, b'wrong')
        self.assertFalse(self.verify_part(1, self.parts[1]).get_json()['result'])
        self.assertEqual(self.post('finish', self.finish_data).get_json(),
                         {'result': False, 'reason': 'checksum fail'})
        self.assertFalse(self.public_path.exists())
        self.assertEqual(self.post('start', self.start_data).get_json()['finished_parts'], [])
        orphan = self.chunk_dir / 'assembly-orphan'
        orphan.mkdir()
        self.put_part(1, self.parts[1])
        self.assertEqual(self.post('finish', self.finish_data).get_json(), {'result': True})
        self.assert_published()

    def test_late_part_never_reopens_completed_upload(self):
        self.prepare()
        self.assertEqual(self.post('finish', self.finish_data).get_json(), {'result': True})
        self.put_part(0, self.parts[0])
        self.assertTrue(self.verify_part(0, self.parts[0]).get_json()['result'])
        self.assert_published()

    def test_simple_upload_keeps_published_multipart_record(self):
        self.prepare()
        self.assertEqual(self.post('finish', self.finish_data).get_json(), {'result': True})
        response = self.post_file('/api/1/upload/file',
                                  {'checksum': self.checksum, 'file': (io.BytesIO(b''.join(self.parts)), 'file')})
        self.assertEqual(response.get_json(), {'result': True})
        self.assert_published()
