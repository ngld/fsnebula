import os.path
import json
from app import app
from app.models import Mod
from app.controllers.mod import render_mod_list

update_required = os.path.join(app.config['FILE_STORAGE'], 'repo_needs_update')
repo_path = os.path.join(app.config['FILE_STORAGE'], 'public', 'repo.json')
lock_path = repo_path + '.lock'

if os.path.isfile(lock_path):
    print('Update already in progress!')
    exit(0)

# if we don't need an update then bail
if not os.path.isfile(update_required):
    exit(0)

open(lock_path, 'w').close()
print('Updating repo...')

try:
    exclude_fields = ('members', 'team', 'releases')

    mods = Mod.objects.exclude(*exclude_fields).select_related(4)
    repo = render_mod_list(mods)

    with open(repo_path, 'w') as stream:
        json.dump({'mods': repo}, stream) # , seperator=(',',':'))
except Exception:
    print('Failed to update repository data!')
else:
    print('Repo update complete.')

os.unlink(lock_path)
os.unlink(update_required)
