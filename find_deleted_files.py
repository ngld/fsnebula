from app.models import ModRelease, UploadedFile

hidden = ModRelease.objects(hidden=True)
for rel in hidden:
  for pkg in rel.packages:
    for archive in pkg.files:
      ref = UploadedFile.objects(checksum=archive.checksum).first()
      if ref:
        print(ref.filename)
