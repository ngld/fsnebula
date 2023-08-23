import os.path
from subprocess import check_call, check_output, CalledProcessError
from mongoengine import DoesNotExist
from mongoengine.queryset.visitor import Q
from app import app
from app.models import UploadedFile, IndexedFile

print('Retrieving uploaded files...')
docs = UploadedFile.objects(Q(indexed=False) | Q(indexed=None))
total = len(docs)
print('Found %d items. Processing...' % total)

mismatches = open('mismatches.txt', 'a')
no_archives = open('no_archives.txt', 'a')
empty = open('empty.txt', 'a')

os.chdir('/tmp/nebula')

done = 0
for doc in docs:
    path = os.path.join(app.config['FILE_STORAGE'], doc.filename)

    done += 1
    print('[%4d / %d]: Verifying hash for %s...' % (done, total, doc.filename))
    text = check_output(['sha256sum', path]).decode('utf8').split(' ')[0]

    if text != doc.checksum:
        print('FAILED!!')
        mismatches.write(doc.filename + '\n')
        doc.indexed = True
        doc.save()
        continue

    print('Extracting...')
    if os.path.isdir('index_tmp'):
        check_call(['rm', '-rf', 'index_tmp'])

    try:
        check_call(['7z', 'x', '-oindex_tmp', path])
    except CalledProcessError:
        print('Not an archive...')
        no_archives.write(doc.filename + '\n')
        doc.indexed = True
        doc.save()
        continue

    if not os.path.isdir('index_tmp'):
        print('Empty!!')
        empty.write(doc.filename + '\n')
        doc.indexed = True
        doc.save()
        continue

    print('Building hashlist...')
    data = check_output(['find', 'index_tmp', '-type', 'f', '-exec', 'sha256sum', '{}', ';']).decode('utf8')

    print('Processing hashlist...')
    for line in data.splitlines():
        ck, name = line.split(' ', 1)

        name = name.strip()
        if name.startswith('index_tmp/'):
            name = name[10:]

        try:
            item = IndexedFile.objects(hash_=ck).get()
        except DoesNotExist:
            item = IndexedFile(hash_=ck, filesize=-1)

        if item.filesize == -1:
            path = os.path.join('index_tmp', name)
            item.filesize = os.stat(path).st_size

        if name not in item.filenames:
            item.filenames.append(name)

        item.archives.append(doc)
        item.save()

    doc.indexed = True
    doc.save()

    print('Cleanup...')
    check_call(['rm', '-rf', 'index_tmp'])
