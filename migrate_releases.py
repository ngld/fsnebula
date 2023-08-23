
from app.models import Mod, ModRelease


for mod in Mod.objects:
    print(mod.title, len(mod.releases))

    for rel in mod.releases:
        attrs = rel._data.copy()
        attrs['mod'] = mod
        ModRelease(**attrs).save()

    mod.releases = []
    mod.save()
