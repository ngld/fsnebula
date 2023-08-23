from app.models import UploadedFile

groups = {}
for f in UploadedFile.objects:
    groups.setdefault(f.content_checksum, []).append(f)

for l in groups.values():
    if len(l) < 2: continue

    if not l[0].content_checksum:
        for f in l:
            if f.duplicate_of:
                print('Fixed content checksumless', f.checksum)
                f.duplicate_of = None
                f.save()

        continue

    master = None
    for f in l:
        if f.vp_checksum:
            master = f
            break

    if master:
        print(master.content_checksum, '->', master.checksum, master.duplicate_of)

        if master.expires != -1:
            master.make_permanent()

        for f in l:
            if f.duplicate_of != master.checksum:
                f.duplicate_of = master.checksum
                f.save()
