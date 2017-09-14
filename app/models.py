import os
import shutil
from mongoengine import (
    Document, EmbeddedDocument, StringField, ListField, BooleanField,
    ReferenceField, IntField, DateTimeField, EmbeddedDocumentListField
)
from flask import url_for
from . import app

__all__ = {'User', 'Dependency', 'Executable', 'ModArchive', 'ModFile', 'Package', 'ModRelease', 'Mod', 'UploadedFile'}


class User(Document):
    username = StringField(primary_key=True, max_length=80)
    email = StringField(required=True, max_length=200)
    password = StringField(required=True, max_length=120)
    groups = ListField(StringField(max_length=80))

    register_token = StringField(max_length=64, default=None)
    reset_token = StringField(max_length=64, default=None)

    active = BooleanField(default=False)


class Dependency(EmbeddedDocument):
    id = StringField(required=True, max_length=120)
    version = StringField(required=True, max_length=32)
    packages = ListField(StringField(max_length=120))


class Executable(EmbeddedDocument):
    file = StringField(required=True, max_length=120)
    debug = BooleanField(default=False)


class ModArchive(EmbeddedDocument):
    filename = StringField(required=True, max_length=120)
    dest = StringField(required=True, max_length=120)
    checksum = StringField(max_length=128)
    filesize = IntField()


class ModFile(EmbeddedDocument):
    filename = StringField(required=True, max_length=120)
    archive = StringField(required=True, max_length=120)
    orig_name = StringField(required=True, max_length=255)
    checksum = ListField(StringField(max_length=128))


class Package(EmbeddedDocument):
    name = StringField(required=True, max_length=120)
    notes = StringField(max_length=10240)
    status = StringField(max_length=20)
    dependencies = EmbeddedDocumentListField(Dependency)
    environment = StringField(max_length=200)
    executables = EmbeddedDocumentListField(Executable)
    files = EmbeddedDocumentListField(ModArchive)
    filelist = EmbeddedDocumentListField(ModFile)


class ModRelease(EmbeddedDocument):
    version = StringField(required=True, max_length=32)
    description = StringField(max_length=10240)
    release_thread = StringField(required=True, max_length=300)
    videos = ListField(StringField(max_length=300))
    notes = StringField(max_length=10240)
    last_update = DateTimeField()
    cmdline = StringField(max_length=300)
    packages = EmbeddedDocumentListField(Package)
    hidden = BooleanField(default=False)


class Mod(Document):
    mid = StringField(required=True, max_length=100, primary_key=True)
    title = StringField(required=True, max_length=200, unique=True)
    type = StringField(max_length=10)
    folder = StringField(max_length=30)
    logo = StringField(required=True, max_length=128)
    tile = StringField(required=True, max_length=128)
    first_release = DateTimeField()
    members = ListField(ReferenceField(User))
    releases = EmbeddedDocumentListField(ModRelease)


class UploadedFile(Document):
    filename = StringField(required=True, max_length=200)
    file_ext = StringField(max_length=10)
    checksum = StringField(primary_key=True, max_length=128)
    mod = ReferenceField(Mod)
    expires = IntField()

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
        return url_for('storage', filename=self.filename[8:], _external=True)

    def make_permanent(self):
        if self.expires == -1:
            return

        old_path = self.filename
        self.expires = -1
        self.gen_filename()

        dest_path = os.path.join(app.config['FILE_STORAGE'], self.filename)

        os.makedirs(dest_path, exist_ok=True)
        shutil.move(os.path.join(app.config['FILE_STORAGE'], old_path), dest_path)
        self.save()