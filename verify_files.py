#!/usr/bin/env python

import os.path
import tempfile
import subprocess
import hashlib

from app.models import Mod, UploadedFile
from app import app


def gen_hash(path, algo='sha256'):
    h = hashlib.new(algo)
    with open(path, 'rb') as stream:
        while True:
            chunk = stream.read(16 * h.block_size)
            if not chunk:
                break

            h.update(chunk)

    return h.hexdigest()


print('Starting...')

chk_cache = dict()

for mod in Mod.objects:
    for rel in mod.releases:
        if rel.hidden:
            continue

        for pkg in rel.packages:
            arnames = {}
            for ar in pkg.files:
                uf = UploadedFile.objects(checksum=ar.checksum).first()
                if uf:
                    arnames[ar.filename] = uf.filename

                if ar.checksum not in chk_cache:
                    if not uf: continue

                    print(
                        'Generating checksums for %s in %s (%s) / %s' %
                        (ar.filename, mod.title, rel.version, pkg.name)
                    )

                    arsums = chk_cache[ar.checksum] = dict()

                    with tempfile.TemporaryDirectory() as cdir:
                        arpath = os.path.abspath(os.path.join(app.config['FILE_STORAGE'], uf.filename))
                        try:
                            subprocess.check_call(['7z', 'x', arpath], cwd=cdir, stdout=subprocess.DEVNULL)
                        except subprocess.CalledProcessError:
                            print('ERROR: Failed to extract %s!' % arpath)
                            continue

                        for sub, dirs, files in os.walk(cdir):
                            relsub = os.path.relpath(sub, cdir)

                            for fn in files:
                                relpath = os.path.join(relsub, fn).replace('\\', '/')
                                arsums[(ar.filename + '/' + relpath).lower()] = gen_hash(os.path.join(cdir, relpath))
                else:
                    arsums = chk_cache[ar.checksum]

            missing_files = False
            diff_csums = False
            for meta in pkg.filelist:
                if meta.orig_name[:2] != './':
                    relpath = meta.archive + '/./' + meta.orig_name
                else:
                    relpath = meta.archive + '/' + meta.orig_name

                phys_csum = arsums.get(relpath.lower())
                if not phys_csum:
                    print(relpath + ' is missing! (%s)' % arnames.get(meta.archive, '???'))
                    missing_files = True
                elif meta.checksum[1] != phys_csum:
                    print(relpath + ' has a wrong checksum! (%s != %s)' % (meta.checksum, phys_csum))
                    diff_csums = True

            if missing_files:
                print('## %s (%s) / %s is missing files!' % (mod.title, rel.version, pkg.name))

            if diff_csums:
                print('## %s (%s) / %s has wrong checksums!' % (mod.title, rel.version, pkg.name))


print('Done')
