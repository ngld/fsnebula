from mongoengine import (
    Document, StringField, ListField, BooleanField, ReferenceField, IntField,
    DateTimeField
)

__all__ = {'User'}


class User(Document):
    username = StringField(required=True, max_length=80)
    email = StringField(required=True, max_length=200)
    password = StringField(required=True, max_length=120)
    groups = ListField(StringField(max_length=80))

    register_token = StringField(max_length=64, default=None)
    reset_token = StringField(max_length=64, default=None)

    active = BooleanField(default=False)


class Dependency(Document):
    id = StringField(required=True, max_length=120)
    version = StringField(required=True, max_length=32)
    packages = ListField(StringField(max_length=120))


class Executable(Document):
    file = StringField(required=True, max_length=120)
    debug = BooleanField(default=False)


class ModArchive(Document):
    filename = StringField(required=True, max_length=120)
    dest = StringField(required=True, max_length=120)
    checksum = ListField(StringField(max_length=128))
    filesize = IntField()
    urls = ListField(StringField(max_length=1024))


class ModFile(Document):
    filename = StringField(required=True, max_length=120)
    archive = StringField(required=True, max_length=120)
    orig_name = StringField(required=True, max_length=255)
    checksum = ListField(StringField(max_length=128))


class Package(Document):
    name = StringField(required=True, max_length=120)
    notes = StringField(max_length=10240)
    status = StringField(max_length=20)
    dependencies = ListField(Dependency)
    environment = StringField(max_length=200)
    executables = ListField(Executable)
    files = ListField(ModArchive)
    filelist = ListField(ModFile)


class Mod(Document):
    mid = StringField(required=True, max_length=100)
    title = StringField(required=True, max_length=200)
    version = StringField(required=True, max_length=32)
    description = StringField(max_length=10240)
    logo = StringField(required=True, max_length=128)
    tile = StringField(required=True, max_length=128)
    release_thread = StringField(required=True, max_length=300)
    videos = ListField(StringField(max_length=300))
    notes = StringField(max_length=10240)
    folder = StringField(max_length=30)
    first_release = DateTimeField()
    last_update = DateTimeField()
    cmdline = StringField(max_length=300)
    type = StringField(max_length=10)
    packages = ListField(Package)


class UploadTicket(Document):
    username = StringField(required=True)
    mod = ReferenceField(Mod)
    expires = IntField(required=True)


class UploadedFile(Document):
    ticket = ReferenceField(UploadTicket)
    pieces = ListField(StringField(max_length=128))
    filename = StringField(required=True, max_length=200)
    finished = BooleanField(default=False)
