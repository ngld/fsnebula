import sys
import os.path
import subprocess
from app.models import Mod, ModRelease, ModFile, UploadedFile

for mid in sys.argv[1:]:
    print(mid)
    mod = Mod.objects(mid=mid).first()
    #for mod in Mod.objects:
    for rel in ModRelease.objects(mod=mod):
        if rel.rebuilt_filelist or rel.version != "4.5.1":
            continue

        print('Processing %s %s...' % (mod.title, rel.version))

        try:
            pkgs = len(rel.packages)
            for i, pkg in enumerate(rel.packages):
                print('[%3d/%3d]: %s' % (i, pkgs, pkg.name))
                ar = pkg.files[0]
                arfile = UploadedFile.objects(checksum=ar.checksum).first()

                os.mkdir('tmp22')
                subprocess.check_call(['7z', 'x', '-otmp22', os.path.join('../uploads', arfile.filename)])

                print('Hashing...')
                cks = subprocess.check_output(['find', '-type', 'f', '-exec', 'sha256sum', '{}', ';'], cwd='tmp22').decode('utf8')

                print('Cleanup...')
                subprocess.check_call(['rm', '-rf', 'tmp22'])

                pkg.filelist = []
                for item in cks.splitlines():
                    ck, name = item.split(' ', 1)
                    name = name.strip()

                    pkg.filelist.append(ModFile(
                        filename=name,
                        archive=ar.filename,
                        orig_name=name,
                        checksum=('sha256', ck)
                    ))

            rel.rebuilt_filelist = True
            rel.save()
        except Exception as ex:
            print(ex)

            if os.path.isdir('tmp22'):
                subprocess.check_call(['rm', '-rf', 'tmp22'])
