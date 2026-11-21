"""Shared setup for the tests: runs the app in-process against mongomock (an
in-memory stand-in for MongoDB) and a throwaway storage folder. Nothing here
talks to a real server unless FSNEBULA_TEST_MONGO is set (see below).

tests/requirements.txt is the app's requirements plus mongomock. On Windows,
python-magic also needs python-magic-bin. Each test file is a script:

    pip install -r tests/requirements.txt
    python tests/test_hardening.py
"""
import atexit
import hashlib
import io
import os
import re
import shutil
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The app reads its settings from the file named by NEBULA_SETTINGS at import
# time, so the settings file has to exist before `app` is imported.
START_DIR = os.getcwd()
ROOT = tempfile.mkdtemp(prefix='fsnebula-tests-')
UPLOADS = os.path.join(ROOT, 'uploads')
for sub in ('public', 'cache', 'chunks', 'temp'):
    os.makedirs(os.path.join(UPLOADS, sub))


def _clean_up():
    os.chdir(START_DIR)
    shutil.rmtree(ROOT, ignore_errors=True)


atexit.register(_clean_up)

# Set FSNEBULA_TEST_MONGO to a mongodb:// address of a throwaway database to
# run the tests on a real MongoDB. Every test drops the collections it uses,
# users and mods included, so the database name has to say it is for tests.
MONGO = os.environ.get('FSNEBULA_TEST_MONGO')
if MONGO is None:
    MONGO = 'mongomock://localhost/nebula'
    print('database: mongomock (in memory)', file=sys.stderr)
else:
    from pymongo.uri_parser import parse_uri
    if not re.search(r'(^|[_-])tests?($|[_-])', parse_uri(MONGO)['database'] or ''):
        sys.exit('FSNEBULA_TEST_MONGO must name a database like "nebula_test": the word "test" or "tests" set '
                 'off by "_" or "-". The tests drop its collections.')
    print('database: the MongoDB named by FSNEBULA_TEST_MONGO', file=sys.stderr)

CFG = os.path.join(ROOT, 'test.cfg')
with open(CFG, 'w') as stream:
    stream.write(
        "DEBUG = False\n"
        "MONGO_DB = %r\n"
        "TOKEN_LIFETIME = 3600\n"
        "JWT_SECRET = b'tests-only'\n"
        "ARGON2_ROUNDS = 1\n"
        "SMTP_SSL = False\nSMTP_STARTTLS = False\nSMTP_HOST = 'localhost'\n"
        "SMTP_PORT = 25\nSMTP_USER = None\nSMTP_PASSWORD = None\n"
        "MAIL_SENDER = 'noreply@example.invalid'\n"
        "FILE_STORAGE = %r\n"
        "MAX_CONTENT_LENGTH = 50 * 1024 * 1024\n"
        "MIME_BLACKLIST = ['application/x-dosexec']\n"
        "ADMIN_MAIL = 'admin@example.invalid'\n"
        "URLS_FOR = []\n"
        "DISCORD_WEBHOOK = None\nDISCORD_NICK = 'Nebula'\n"
        "IMAGE_SERVER = 'https://img.example.invalid'\n"
        "DL_MIRRORS = ['https://dl.example.invalid/storage']\n" % (MONGO, UPLOADS)
    )

os.environ['NEBULA_SETTINGS'] = CFG
sys.path.insert(0, REPO)
# The app's storage paths are relative to the working folder in places.
os.chdir(ROOT)

from app import app, models  # noqa: E402
from app.helpers import generate_token, hash_password  # noqa: E402
from app.controllers import mod as mod_ctl  # noqa: E402

# mongomock has no text index, which Log asks for.
models.Log._meta['auto_create_index'] = False

client = app.test_client()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def make_user(name):
    models.User(username=name, email=name + '@example.invalid',
                password=hash_password('pw12345'), active=True).save()
    return {'X-KN-TOKEN': generate_token(name)}


def upload_small(headers, data, checksum=None):
    return client.post('/api/1/upload/file', headers=headers,
                       data={'checksum': checksum or sha(data), 'file': (io.BytesIO(data), 'f.bin')},
                       content_type='multipart/form-data')


def send_chunks(headers, upload_id, data):
    client.post('/api/1/multiupload/start', headers=headers,
                data={'id': upload_id, 'size': str(len(data)), 'parts': '1'})
    client.post('/api/1/multiupload/part', headers=headers,
                data={'id': upload_id, 'part': '0', 'file': (io.BytesIO(data), 'p')},
                content_type='multipart/form-data')


def finish(headers, upload_id, checksum):
    return client.post('/api/1/multiupload/finish', headers=headers,
                       data={'id': upload_id, 'checksum': checksum})


def upload_chunked(headers, upload_id, data, checksum):
    send_chunks(headers, upload_id, data)
    return finish(headers, upload_id, checksum)


def create_mod(headers, mid, title=None):
    return client.post('/api/1/mod/create', headers=headers, json={
        'id': mid, 'title': title or 'Title ' + mid, 'type': 'mod', 'logo': '', 'tile': ''})


def release(headers, mid, version, archive_sum, pkg_name='core', notes='', archive_name='a.7z'):
    return client.post('/api/1/mod/release', headers=headers, json={
        'id': mid, 'version': version, 'mod_flag': [],
        'packages': [{
            'name': pkg_name, 'notes': notes,
            'files': [{'filename': archive_name, 'dest': '', 'filesize': 3,
                       'checksum': ['sha256', archive_sum]}],
            'filelist': [{'filename': 'x.txt', 'archive': archive_name, 'orig_name': 'x.txt',
                          'checksum': ['sha256', '00']}],
        }]})


def stored_tree():
    """Every file and folder under the storage root, as relative paths."""
    found = set()
    for base, dirs, names in os.walk(UPLOADS):
        for name in dirs + names:
            found.add(os.path.relpath(os.path.join(base, name), UPLOADS))
    return found


class Base(unittest.TestCase):
    def setUp(self):
        for name in ('User', 'Mod', 'ModRelease', 'UploadedFile', 'ChunkedUpload', 'Log'):
            getattr(models, name).drop_collection()


class PublishedFile(Base):
    """Base for tests that start from a file a release already uses."""

    def publish(self, headers, data):
        upload_small(headers, data)
        create_mod(headers, 'pubmod')
        release(headers, 'pubmod', '1.0.0', sha(data))
        self.assertEqual(models.UploadedFile.objects(checksum=sha(data)).first().expires, -1)

    def assert_still_published(self, data):
        record = models.UploadedFile.objects(checksum=sha(data)).first()
        self.assertIsNotNone(record)
        self.assertEqual(record.expires, -1)
        self.assertTrue(os.path.isfile(os.path.join(UPLOADS, record.filename)))
        with open(os.path.join(UPLOADS, record.filename), 'rb') as stream:
            self.assertEqual(stream.read(), data)
        self.assertTrue(client.get('/api/1/mod/json/pubmod/1.0.0').get_json()['result'])
        mod_ctl.render_mod_list(list(models.Mod.objects))
