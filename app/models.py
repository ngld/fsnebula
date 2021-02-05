import os
import shutil
from mongoengine import (
    Document, EmbeddedDocument, StringField, ListField, BooleanField,
    ReferenceField, IntField, DateTimeField, EmbeddedDocumentListField,
    LazyReferenceField, CASCADE
)
from flask import url_for
from . import app

__all__ = {'User', 'Dependency', 'Executable', 'ModArchive', 'ModFile', 'Package', 'ModRelease', 'Mod', 'UploadedFile', 'IndexedFile', 'ChunkedUpload'}


class User(Document):
    username = StringField(primary_key=True, max_length=80)
    email = StringField(required=True, max_length=200)
    password = StringField(required=True, max_length=120)
    token = StringField(max_length=120)
    groups = ListField(StringField(max_length=80))

    register_token = StringField(max_length=64, default=None)
    reset_token = StringField(max_length=64, default=None)

    active = BooleanField(default=False)


class Dependency(EmbeddedDocument):
    id = StringField(required=True, max_length=120)
    version = StringField(max_length=32)
    packages = ListField(StringField(max_length=120))


class Executable(EmbeddedDocument):
    file = StringField(required=True, max_length=120)
    label = StringField(max_length=128, default=None)


class ModArchive(EmbeddedDocument):
    filename = StringField(required=True, max_length=120)
    dest = StringField(required=True, max_length=120)
    checksum = StringField(max_length=128)
    filesize = IntField()
    urls = ListField(StringField(max_length=400))


class ModFile(EmbeddedDocument):
    filename = StringField(required=True, max_length=500)
    archive = StringField(required=True, max_length=120)
    orig_name = StringField(required=True, max_length=255)
    checksum = ListField(StringField(max_length=128))


class Package(EmbeddedDocument):
    name = StringField(required=True, max_length=120)
    notes = StringField(max_length=10240)
    status = StringField(max_length=20)
    dependencies = EmbeddedDocumentListField(Dependency)
    environment = StringField(max_length=200)
    folder = StringField(max_length=200)
    is_vp = BooleanField(default=False)
    executables = EmbeddedDocumentListField(Executable)
    files = EmbeddedDocumentListField(ModArchive)
    filelist = EmbeddedDocumentListField(ModFile)


class OldModRelease(EmbeddedDocument):
    version = StringField(required=True, max_length=32)
    stability = StringField(max_length=60)
    description = StringField(max_length=10240)
    release_thread = StringField(max_length=300)
    banner = StringField(max_length=128)
    videos = ListField(StringField(max_length=300))
    screenshots = ListField(StringField(max_length=128))
    attachments = ListField(StringField(max_length=128))
    notes = StringField(max_length=10240)
    last_update = DateTimeField()
    cmdline = StringField(max_length=1000)
    mod_flag = ListField(StringField(max_length=100))
    packages = EmbeddedDocumentListField(Package)
    hidden = BooleanField(default=False)
    private = BooleanField(default=False)


class ModRelease(Document):
    mod = LazyReferenceField('Mod', required=True)
    version = StringField(required=True, max_length=32)
    stability = StringField(max_length=60)
    description = StringField(max_length=10240)
    release_thread = StringField(max_length=300)
    banner = StringField(max_length=128)
    videos = ListField(StringField(max_length=300))
    screenshots = ListField(StringField(max_length=128))
    attachments = ListField(StringField(max_length=128))
    notes = StringField(max_length=10240)
    last_update = DateTimeField()
    cmdline = StringField(max_length=1000)
    mod_flag = ListField(StringField(max_length=100))
    packages = EmbeddedDocumentListField(Package)
    hidden = BooleanField(default=False)
    private = BooleanField(default=False)
    rebuilt_filelist = BooleanField(default=False)

    meta = {
      'indexes': ['mod', ('private', 'hidden')]
    }


TEAM_OWNER = 0
TEAM_MANAGER = 10
TEAM_UPLOADER = 20
TEAM_TESTER = 30

class TeamMember(EmbeddedDocument):
    user = ReferenceField(User)
    # Possible values: owner, uploader, tester
    role = IntField(required=True)


class Mod(Document):
    mid = StringField(required=True, max_length=100, primary_key=True)
    title = StringField(required=True, max_length=200)
    type = StringField(max_length=10)
    parent = StringField(max_length=100)
    logo = StringField(max_length=128)
    tile = StringField(max_length=128)
    tags = ListField(StringField(max_length=100))
    first_release = DateTimeField()
    members = ListField(ReferenceField(User))
    team = EmbeddedDocumentListField(TeamMember)
    releases = EmbeddedDocumentListField(OldModRelease)


Mod.register_delete_rule(ModRelease, 'mod', CASCADE)
class UploadedFile(Document):
    filename = StringField(required=True, max_length=200)
    file_ext = StringField(max_length=10)
    checksum = StringField(primary_key=True, max_length=128)
    content_checksum = StringField(max_length=128)
    is_vp = BooleanField(default=False)
    vp_checksum = StringField(max_length=128)
    duplicate_of = StringField(max_length=128)
    filesize = IntField()
    mod = ReferenceField(Mod)
    expires = IntField()
    indexed = BooleanField(default=False)

    meta = {
        'indexes': [
            'content_checksum'
        ]
    }

    def gen_filename(self):
        if self.expires != -1:
            self.filename = 'temp/' + self.checksum
        else:
            self.filename = 'public/%s/%s/%s' % (self.checksum[:2],
                self.checksum[2:4], self.checksum[4:])

        if self.file_ext:
            self.filename += '.' + self.file_ext

    def get_url(self):
        if self.expires != -1:
            raise ValueError()

        # Strip off the "public/" prefix
        return app.config['IMAGE_SERVER'] + '/' + self.filename[7:]

    def get_urls(self):
        if self.expires != -1:
            raise ValueError()

        # Strip off the "public/" prefix
        slug = '/' + self.filename[7:]
        return [prefix + slug for prefix in app.config['DL_MIRRORS']]

    def make_permanent(self):
        if self.expires == -1:
            return

        old_path = self.filename
        self.expires = -1
        self.gen_filename()

        dest_path = os.path.join(app.config['FILE_STORAGE'], self.filename)

        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        shutil.move(os.path.join(app.config['FILE_STORAGE'], old_path), dest_path)
        self.save()


class ChunkedUpload(Document):
    id = StringField(primary_key=True, max_length=128)
    filesize = IntField(required=True)
    total_parts = IntField(required=True)
    finished_parts = ListField(IntField(required=True))
    chunksize = IntField(default=-1)
    done = BooleanField(default=False)
    expires = IntField()


class IndexedFile(Document):
    hash_ = StringField(primary_key=True, max_length=128)
    filenames = ListField(StringField(required=True, max_length=200))
    archives = ListField(LazyReferenceField(UploadedFile, required=True))
    filesize = IntField(required=True)


class Log(Document):
    uploaded = DateTimeField()
    content = StringField()

    meta = {
        'indexes': ['$content']
    }
