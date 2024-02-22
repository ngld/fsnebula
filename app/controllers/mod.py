import os.path
import json
import semantic_version
import requests
from datetime import datetime
from email.message import EmailMessage
from urllib.parse import urlparse
from flask import request, jsonify, abort, url_for, render_template
from mongoengine.errors import ValidationError

from .. import app
from ..helpers import verify_token, send_mail
from ..models import (
    Dependency, Executable, ModArchive, ModFile, Package, ModRelease, Mod, UploadedFile, TeamMember, User,
    TEAM_OWNER, TEAM_MANAGER, TEAM_UPLOADER, TEAM_TESTER
)


@app.route('/api/1/mod/check_id', methods={'POST'})
def check_mod_id():
    user = verify_token()
    if not user:
        abort(403)

    mod = Mod.objects(mid=request.form['id']).first()
    return jsonify(result=not mod)


@app.route('/api/1/mod/create', methods={'POST'})
def create_mod():
    user = verify_token()
    if not user:
        abort(403)

    meta = request.get_json()
    if not meta:
        abort(400)

    first_rel = None
    if meta.get('first_release'):
        try:
            first_rel = datetime.strptime(meta['first_release'], '%Y-%m-%d')
        except ValueError:
            pass

    if not first_rel:
        first_rel = datetime.now()

    mod = Mod(mid=meta['id'],
              title=meta['title'],
              type=meta['type'],
              parent=meta.get('parent', 'FS2'),
              first_release=first_rel,
              team=[TeamMember(user=user, role=TEAM_OWNER)])

    for prop in ('logo', 'tile'):
        if meta[prop] != '':
            image = UploadedFile.objects(checksum=meta[prop]).first()

            if image:
                image.make_permanent()
                setattr(mod, prop, image.checksum)

    try:
        mod.save(True)
    except ValueError:
        app.logger.exception('Failed to store new mod!')
        return jsonify(result=False)

    return jsonify(result=True)


@app.route('/api/1/mod/update', methods={'POST'})
def update_mod():
    user = verify_token()
    if not user:
        abort(403)

    meta = request.get_json()
    if not meta:
        abort(400)

    mod = Mod.objects(mid=meta['id']).first()
    if not mod:
        abort(404)

    role = None
    for member in mod.team:
        if member.user == user:
            role = member.role
            break

    if role is None or role > TEAM_UPLOADER:
        return jsonify(result=False, reason='unauthorized')

    if meta.get('first_release'):
        try:
            mod.first_release = datetime.strptime(meta['first_release'], '%Y-%m-%d')
        except ValueError:
            pass

    mod.title = meta['title']

    for prop in ('logo', 'tile'):
        if meta[prop] != '':
            image = UploadedFile.objects(checksum=meta[prop]).first()

            if image:
                image.make_permanent()
                setattr(mod, prop, image.checksum)
            else:
                setattr(mod, prop, None)
        else:
            setattr(mod, prop, None)

    mod.save()
    return jsonify(result=True)


@app.route('/api/1/mod/create_or_update', methods={'POST'})
def create_or_update_mod():
    user = verify_token()
    if not user:
        abort(403)

    meta = requests.get_json()

    if not meta:
        abort(400)

    first_rel = None
    if meta.get('first_release'):
        try:
            first_rel = datetime.strptime(meta['first_release'], '%Y-%m-%d')
        except ValueError:
            pass

    mod = Mod.objects(mid=meta['id']).first()
    if not mod:
        if not first_rel:
            first_rel = datetime.now()

        mod = Mod(mid=meta['id'],
                  title=meta['title'],
                  type=meta['type'],
                  parent=meta.get('parent', 'FS2'),
                  first_release=first_rel,
                  team=[TeamMember(user=user, role=TEAM_OWNER)])
    else:
        role = None
        for member in mod.team:
            if member.user == user:
                role = member.role
                break

        if role is None or role > TEAM_UPLOADER:
            return jsonify(result=False, reason='unauthorized')

        if first_rel:
            mod.first_release = first_rel

        mod.title = meta['title']

    for prop in ('logo', 'tile'):
        if meta[prop] != '':
            image = UploadedFile.objects(checksum=meta[prop]).first()

            if image:
                image.make_permanent()
                setattr(mod, prop, image.checksum)
            else:
                setattr(mod, prop, None)
        else:
            setattr(mod, prop, None)

    try:
        mod.save()
    except ValueError:
        app.logger.exception('Failed to store new mod!')
        return jsonify(result=False)

    return jsonify(result=True)


def _do_preflight(save=False, ignore_duplicate=False):
    user = verify_token()
    if not user:
        abort(403)

    meta = request.get_json()
    if not meta:
        abort(400)

    mod = Mod.objects(mid=meta['id']).first()
    if not mod:
        abort(404)

    role = None
    for member in mod.team:
        if member.user == user:
            role = member.role
            break

    if role is None or role > TEAM_UPLOADER:
        return meta, mod, None, user, 'unauthorized'

    if meta.get('chunked_upload', False):
        release = ModRelease.objects(mod=mod, version=meta['version'], hidden=True).first()
        if release:
            return meta, mod, release, user, None

    release = ModRelease(
        mod=mod,
        version=meta['version'],
        description=meta.get('description', ''),
        release_thread=meta.get('release_thread', None),
        videos=meta.get('videos', []),
        notes=meta.get('notes', ''),
        last_update=datetime.now(),
        cmdline=meta.get('cmdline', ''),
        mod_flag=meta.get('mod_flag', ''),
        private=meta.get('private', False),
        hidden=meta.get('chunked_upload', False))

    if mod.type == 'engine':
        release.stability = meta.get('stability', 'stable')

    try:
        new_ver = semantic_version.Version(meta['version'])
    except ValueError:
        app.logger.exception('Invalid version "%s" provided during preflight check!' % meta['version'])
        return meta, mod, None, user, 'invalid version'

    if not ignore_duplicate:
        for rel in ModRelease.objects(mod=mod).only('version'):
            try:
                rv = semantic_version.Version(rel.version)
            except ValueError:
                app.logger.exception('Mod %s has an invalid version %s!' % (mod.mid, rel.version))
                continue

            if rv == new_ver:
                return meta, mod, release, user, 'duplicated version'

    img_url_allow = user.username in app.config['URLS_FOR']
    if meta.get('banner'):
        if meta['banner'].startswith('http') and img_url_allow:
            release.banner = meta['banner']
        else:
            image = UploadedFile.objects(checksum=meta['banner']).first()

            if image:
                if save:
                    image.make_permanent()

                release.banner = image.checksum

    for prop in ('screenshots', 'attachments'):
        checked = []
        for chk in meta.get(prop, []):
            if chk.startswith('http') and img_url_allow:
                checked.append(chk)
            else:
                image = UploadedFile.objects(checksum=chk).first()

                if image:
                    if save:
                        image.make_permanent()

                    checked.append(chk)

        setattr(release, prop, checked)

    return meta, mod, release, user, None


@app.route('/api/1/mod/release/preflight', methods={'POST'})
def preflight_release():
    meta, mod, rel, user, resp = _do_preflight()
    if resp is None:
        return jsonify(result=True)
    else:
        return jsonify(result=False, reason=resp)


def announce_release(release, mod):
    if not app.config['DISCORD_WEBHOOK']:
        return

    try:
        img = release.banner or mod.logo
        if img:
            if '://' in img:
                img = {'url': img}
            else:
                img = UploadedFile.objects(checksum=img).first()

                if img:
                    img = {'url': img.get_url()}

        if not img:
            img = None

        type_names = {
            'mod': 'Mod',
            'engine': 'Build',
            'tc': 'Total Conversion'
        }

        requests.post(app.config['DISCORD_WEBHOOK'], json={
            'username': app.config['DISCORD_NICK'],
            'avatar_url': url_for('static', filename='avatar.png', _external=True).replace('api.fsnebula', 'cf.fsnebula'),
            'embeds': [{
                'url': url_for('view_mod', mid=mod.mid, _external=True).replace('api.fsnebula', 'fsnebula'),
                'title': '%s %s %s released!' % (type_names.get(mod.type, ''), mod.title, release.version),
                'image': img
            }]
        })
    except Exception:
        app.logger.exception('Failed to execute Discord webhook!')


@app.route('/api/1/mod/release', methods={'POST'})
def create_release():
    meta, mod, release, user, error = _do_preflight(save=True)
    if error:
        app.logger.error('Rejecting release for mod %s due to %s', mod.mid, error)
        return jsonify(result=False, reason=error)

    files = []
    for pmeta in meta['packages']:
        pkg = Package(
            name=pmeta['name'],
            notes=pmeta.get('notes', ''),
            status=pmeta.get('status', 'recommended'),
            environment=pmeta.get('environment', ''),
            folder=pmeta.get('folder'),
            is_vp=pmeta.get('is_vp', False))

        for dmeta in pmeta.get('dependencies', []):
            dep = Dependency(id=dmeta['id'], version=dmeta.get('version', None), packages=dmeta.get('packages', []))
            pkg.dependencies.append(dep)

        for emeta in pmeta.get('executables', []):
            exe = Executable(file=emeta['file'], label=emeta['label'])
            pkg.executables.append(exe)

        check_map = {}
        for ameta in pmeta['files']:
            if ameta['checksum'][0] != 'sha256':
                app.logger.error('Unsupported checksum for mod %s found: %s', mod.mid, ameta['checksum'][0])
                return jsonify(result=False, reason='unsupported archive checksum')

            archive = ModArchive(filename=ameta['filename'],
                                 dest=ameta['dest'],
                                 checksum=ameta['checksum'][1],
                                 filesize=ameta['filesize'])

            if 'urls' in ameta:
                if user.username not in app.config['URLS_FOR']:
                    app.logger.error('Found URLs in upload for mod %s from %s', mod.mid, user.username)
                    return jsonify(result=False, reason='urls unauthorized')

                archive.urls = ameta['urls']
            else:
                file = UploadedFile.objects(checksum=archive.checksum).first()
                if not file:
                    app.logger.error('Missing file %s (%s) for mod %s', ameta['filename'], archive.checksum, mod.mid)
                    return jsonify(result=False, reason='archive missing', archive=ameta['filename'])

                #if file.duplicate_of:
                #    orig = UploadedFile.objects(checksum=file.duplicate_of).first()
                #    if orig:
                #        check_map[ameta['filename']] = orig.vp_checksum
                #        file = orig
                #        archive.checksum = orig.checksum

                files.append(file)

            pkg.files.append(archive)

        for fmeta in pmeta['filelist']:
            #if fmeta['archive'] in check_map:
            #    fmeta['checksum'] = ['sha256', check_map[fmeta['archive']]]

            # Workaround
            if not isinstance(fmeta['checksum'], list):
                fmeta['checksum'] = ['sha256', fmeta['checksum']]

            file = ModFile(filename=fmeta['filename'],
                           archive=fmeta['archive'],
                           orig_name=fmeta['orig_name'],
                           checksum=fmeta['checksum'])

            pkg.filelist.append(file)

        release.packages.append(pkg)

    if meta.get('chunked_upload', False):
        pkg_names = set([pkg.name for pkg in release.packages])
        if not set(meta['chunks']) - pkg_names:
            # All chunks have arrived
            release.hidden = False

    try:
        release.save()
    except ValidationError as exc:
        app.logger.error('Failed to save release for mod %s due to %s', mod.mid, exc)
        return jsonify(result=False, reason=str(exc))

    for file in files:
        if not file.mod:
            file.mod = mod

        file.make_permanent()

    if not release.hidden:
        if release.private:
            generate_private_repo(mod)
        else:
            generate_repo()

    if not release.private and not release.hidden and not (mod.mid == 'FSO' and release.stability == 'nightly'):
        announce_release(release, mod)

    return jsonify(result=True)


@app.route('/api/1/mod/release/update', methods={'POST'})
def update_release():
    meta, mod, release, user, error = _do_preflight(save=True, ignore_duplicate=True)
    if error:
        return jsonify(result=False, reason=error)

    old_rel = ModRelease.objects(mod=mod, version=release.version).first()
    if not old_rel:
        return jsonify(result=False, reason='release missing')

    pkg_meta = {}
    for pmeta in meta['packages']:
        pkg_meta[pmeta['name']] = pmeta

    for pkg in old_rel.packages:
        if pkg.name not in pkg_meta:
            continue

        pmeta = pkg_meta[pkg.name]

        # Update everything except for files and filelist
        pkg.notes = pmeta['notes']
        pkg.status = pmeta['status']
        pkg.environment = pmeta['environment']
        pkg.folder = pmeta.get('folder', None)
        pkg.is_vp = pmeta['is_vp']
        pkg.dependencies = []
        pkg.executables = []

        for dmeta in pmeta['dependencies']:
            dep = Dependency(id=dmeta['id'], version=dmeta.get('version', None), packages=dmeta.get('packages', []))
            pkg.dependencies.append(dep)

        for emeta in pmeta['executables']:
            exe = Executable(file=emeta['file'], label=emeta['label'])
            pkg.executables.append(exe)

        release.packages.append(pkg)

    # Overwrite the old release with the new one
    release.id = old_rel.id
    release.save()

    if release.private:
        generate_private_repo(mod)
    else:
        generate_repo()

        if old_rel.private and not release.hidden:
            announce_release(release, mod)

    return jsonify(result=True)


@app.route('/api/1/mod/release/delete', methods={'POST'})
def delete_release():
    user = verify_token()
    if not user:
        abort(403)

    mod = Mod.objects(mid=request.form['mid']).first()
    if not mod:
        abort(404)

    role = None
    for mem in mod.team:
        if mem.user == user:
            role = mem.role
            break

    if role is None or role > TEAM_UPLOADER:
        return jsonify(result=False, reason='unauthorized')

    version = request.form['version']
    release = ModRelease.objects(mod=mod, version=version).first()
    if not release:
        abort(404)

    release.hidden = True
    release.save()

    if release.private:
        generate_private_repo(mod)
    else:
        generate_repo()

    return jsonify(result=True)


@app.route('/api/1/mod/release/report', methods={'POST'})
def report_release():
    user = verify_token()
    if not user:
        abort(403)

    mod = Mod.objects(mid=request.form['mid']).first()
    if not mod:
        abort(404)

    version = request.form['version']
    release = ModRelease.objects(mod=mod, version=version).first()
    if not release:
        abort(404)

    msg = EmailMessage()
    msg['To'] = app.config['ADMIN_MAIL']
    msg['Subject'] = 'FSNebula Abuse Report - %s %s' % (mod.title, version)
    msg.set_content('User: %s\nMessage:\n%s' % (user.username, request.form['message']))
    send_mail(msg)

    return jsonify(result=True)


@app.route('/api/1/mod/team/fetch', methods={'POST'})
def list_team_members():
    user = verify_token()
    if not user:
        abort(403)

    mod = Mod.objects(mid=request.form['mid']).first()
    if not mod:
        return jsonify(result=False, reason='missing')

    role = None
    for mem in mod.team:
        if mem.user == user:
            role = mem.role
            break

    if role is None or role > TEAM_MANAGER:
        return jsonify(result=False, reason='unauthorized')

    return jsonify(result=True, members=[{
        'user': mem.user.username,
        'role': mem.role
    } for mem in mod.team])


@app.route('/api/1/mod/team/update', methods={'POST'})
def update_team_members():
    user = verify_token()
    if not user:
        abort(403)

    params = request.get_json()
    if not params or 'mid' not in params or 'members' not in params:
        abort(403)

    mod = Mod.objects(mid=params['mid']).first()
    if not mod:
        abort(404)

    for mem in params['members']:
        if isinstance(mem['role'], str):
            try:
                mem['role'] = int(mem['role'])
            except ValueError:
                abort(400)

    role = None
    for mem in mod.team:
        if mem.user == user:
            role = mem.role
            break

    if role is None or role > TEAM_MANAGER:
        abort(403)

    if role > TEAM_OWNER:
        old_owners = [mem.user.username for mem in mod.team if mem.role <= TEAM_OWNER]
        new_owners = [mem['user'] for mem in params['members'] if mem['role'] <= TEAM_OWNER]

        old_owners.sort()
        new_owners.sort()

        if old_owners != new_owners:
            return jsonify(result=False, reason='owners_changed')

    has_owners = False
    for mem in params['members']:
        if mem['role'] <= TEAM_OWNER:
            has_owners = True
            break

    if not has_owners:
        return jsonify(result=False, reason='no_owners')

    new_members = []
    for mem in params['members']:
        mem_user = User.objects(username=mem['user']).first()
        if not mem_user:
            return jsonify(result=False, reason='member_not_found', member=mem['user'])

        new_members.append(TeamMember(user=mem_user, role=mem['role']))

    mod.team = new_members
    mod.save()
    return jsonify(result=True)


# NOTE: This is deprecated and will be removed in the future
@app.route('/api/1/mod/editable', methods={'GET'})
def get_editable_mods():
    user = verify_token()
    if not user:
        abort(403)

    mods = [mod.mid for mod in Mod.objects(__raw__={
        'team': {
            '$elemMatch': {
                'user': user.username,
                'role': {'$lte': TEAM_UPLOADER}
            }
        }
    })]
    return jsonify(result=True, mods=mods)


@app.route('/api/1/mod/is_editable', methods={'POST'})
def is_editable():
    user = verify_token()
    if not user:
        abort(403)

    mod = Mod.objects(mid=request.form['mid']).first()
    if not mod:
        return jsonify(result=True, missing=True)

    role = None
    for mem in mod.team:
        if mem.user == user:
            role = mem.role
            break

    return jsonify(result=role is not None and role <= TEAM_UPLOADER, missing=False)


@app.route('/api/1/mod/json/<mid>/<version>', methods={'GET'})
def get_mod_json(mid, version):
    exclude_fields = ('members', 'releases')
    mod = Mod.objects(mid=mid).exclude(*exclude_fields).first()
    if not mod:
        return jsonify(result=False, reason='mod_not_found')

    cond = {}

    # make sure that we don't pass some weird stuff to the db
    try:
        ver = semantic_version.Version(version)
        cond['version'] = str(ver)
    except ValueError:
        return jsonify(result=False, reason='invalid_version_string')

    try:
        repo = render_mod_list([mod], False, False, cond)

        if len(repo) < 1:
            return jsonify(result=False, reason='not_found')

        owners = []
        for mem in mod.team:
            if mem.role <= TEAM_OWNER:
                owners.append(mem.user.username)

        repo[0]['owners'] = owners

        return jsonify(result=True, mod=repo[0])
    except Exception:
        return jsonify(result=False, reason='repo_error')


@app.route('/api/1/mod/rebuild_repo', methods={'GET'})
def rebuild_repo():
    # TODO Access check
    generate_repo()

    return jsonify(result=True)


@app.route('/mods', methods={'GET'})
def list_mods():
    mods = Mod.objects.only('title', 'mid').select_related()
    rels = ModRelease.objects(hidden=False, private=False, mod__in=mods).only('mod').all()
    visible = set([rel.mod.id for rel in rels])
    results = []

    for mod in mods:
        if mod.id in visible:
            results.append(mod)

    results.sort(key=lambda el: el.title)
    return render_template('mod_list.html.j2', mods=results)


@app.route('/mod/<mid>', methods={'GET'})
@app.route('/mod/<mid>/<version>', methods={'GET'})
def view_mod(mid, version=None):
    mod = Mod.objects(mid=mid).first()
    if not mod:
        abort(404)

    cond = {
        'mod': mod,
        'hidden': False,
        'private': False
    }

    if version and version != 'all':
        cond['version'] = version

    if version != 'all':
        fields = ('banner', 'version', 'last_update', 'packages.name', 'packages.notes', 'packages.files')
    else:
        fields = ('banner', 'version', 'last_update')

    rels = list(ModRelease.objects(**cond).only(*fields).all())
    if len(rels) < 1:
        abort(404)

    rels.sort(key=lambda rel: rel.last_update)

    if not rels:
        abort(404)

    rel = rels[-1]
    banner = None

    if rel.banner:
        b = UploadedFile.objects(checksum=rel.banner).first()
        if b:
            banner = b.get_url()

    if version != 'all':
        has_mod_ini = False
        rel.reload(fields=('packages.filelist.filename'))
        for pkg in rel.packages:
            for item in pkg.filelist:
                if item['filename'] == 'mod.ini':
                    has_mod_ini = True
                    break

            if has_mod_ini:
                break

        dl_links = {}
        for pkg in rel.packages:
            for archive in pkg.files:
                if archive.urls:
                    urls = archive.urls
                else:
                    ar = UploadedFile.objects(checksum=archive.checksum).first()
                    if ar:
                        urls = [url + '/rn/' + archive.filename for url in ar.get_urls()]
                    else:
                        urls = None

                if urls:
                    dl_links[archive.checksum] = [(url, urlparse(url).netloc) for url in urls]

        return render_template('mod_install.html.j2', mod={
            'id': mod.mid,
            'title': mod.title,
            'version': rel.version,
            'last_update': rel.last_update,
            'banner': banner,
            'dl_links': dl_links,
            'packages': rel.packages,
            'has_mod_ini': has_mod_ini
        })
    else:
        return render_template('mod_versions.html.j2', versions=reversed(rels), mod={
            'id': mod.mid,
            'title': mod.title,
            'banner': banner
        })


@app.route('/api/1/mod/list_private', methods={'GET'})
def private_repo():
    user = verify_token()
    if not user:
        abort(403)

    mods = Mod.objects(__raw__={
        'team': {
            '$elemMatch': {
                'user': user.username,
                'role': {'$lte': TEAM_TESTER}
            }
        }
    }).select_related()

    #app.logger.info('Private for: %s' % user.username)

    repo = []
    for mod in mods:
        repo_path = os.path.join(app.config['FILE_STORAGE'], 'cache', 'mod_%s.json' % mod.id)
        #app.logger.info('Adding %s (%s)...' % (mod.title, mod.id))

        if os.path.isfile(repo_path):
            with open(repo_path, 'r') as stream:
                content = stream.read()[1:-1]
                if content != '':
                    repo.append(content)

            #app.logger.info('Now %d releases.' % len(repo))
        else:
            rels = json.dumps(render_mod_list([mod], private=True), separators=(',',':'))
            with open(repo_path, 'w') as stream:
                stream.write(rels)

            content = rels[1:-1]
            if content != '':
                repo.append(content)
            #app.logger.info('Rendered. Now %d releases.' % len(repo))

    return '{"result":true,"mods":[%s]}' % ','.join(repo)

    #return json.dumps({'result': True, 'mods': repo}, separators=(',',':'))
    #return json.dumps({'result': True, 'mods': render_mod_list(mods, True)}) #, seperators=(',',':'))


@app.route('/api/1/repo/private', methods={'GET'})
def private_repo_v2():
    user = verify_token()
    if not user:
        abort(403)

    mods = Mod.objects(__raw__={
        'team': {
            '$elemMatch': {
                'user': user.username,
                'role': {'$lte': TEAM_TESTER}
            }
        }
    }).select_related()

    repo = []
    for mod in mods:
        repo_path = os.path.join(app.config['FILE_STORAGE'], 'cache', 'mod2_%s.json' % mod.id)

        if os.path.isfile(repo_path):
            with open(repo_path, 'r') as stream:
                content = stream.read()[1:-1]
                if content != '':
                    repo.append(content)

    return '{"result:true,"mods":[%s]}' % ','.join(rels)


@app.route('/api/1/repo/checksums', methods={'POST'})
def fetch_checksums():
    try:
        mods = json.loads(request.form['mods'])
    except ValueError:
        abort(400)

    result = {}
    for mid, mvs in mods.items():
        mod = Mod.objects(mid=mid).first()
        mrs = (ModRelease
            .objects(m=mod, version__in=mvs, hidden=False, private=False)
            .only('version')
            .only('packages.name')
            .only('packages.filelist')
            .as_pymongo())

        result[mid] = mod_res = {}

        for r in mrs:
            mod_res[r['version']] = r['package']

    return jsonify(result=result)


@app.route('/api/1/repo/mirrors', methods={'GET'})
def get_dl_mirrors():
    return jsonify(result=app.config['DL_MIRRORS'])


def render_mod_list(mods, private=False, no_chksum=False, extra_cond={}):
    repo = []
    files = {}
    rel_map = {}

    for rel in ModRelease.objects(hidden=False, private=private, mod__in=mods, **extra_cond).select_related(4):
        rel_map.setdefault(rel.mod.id, []).append(rel)

    # Retrieve all file references in a single query
    for mod in mods:
        if mod.logo:
            files[mod.logo] = None

        if mod.tile:
            files[mod.tile] = None

        for rel in rel_map.get(mod.id, []):
            if rel.banner:
                files[rel.banner] = None

            for csum in rel.screenshots:
                if '://' not in csum:
                    files[csum] = None

            for csum in rel.attachments:
                if '://' not in csum:
                    files[csum] = None

            for pkg in rel.packages:
                for ar in pkg.files:
                    if not ar.urls:
                        files[ar.checksum] = None

    for item in UploadedFile.objects(checksum__in=files.keys()):
        files[item.checksum] = item

    missing = []
    for item in files.values():
      if item and item.duplicate_of and item.duplicate_of not in files:
        missing.append(item.duplicate_of)

    if missing:
      for item in UploadedFile.objects(checksum__in=missing):
        files[item.checksum] = item

    for mod in mods:
        logo = files.get(mod.logo)
        tile = files.get(mod.tile)

        for rel in rel_map.get(mod.id, []):
            if rel.hidden or rel.private != private:
                continue

            if rel.banner and '://' in rel.banner:
                banner = rel.banner
            else:
                banner = files.get(rel.banner)
                if banner:
                    banner = banner.get_url()

            rmeta = {
                'id': mod.mid,
                'title': mod.title,
                'version': rel.version,
                'private': rel.private,
                'stability': rel.stability if mod.type == 'engine' else None,
                'parent': mod.parent,
                'description': rel.description,
                'logo': logo and logo.get_url() or None,
                'tile': tile and tile.get_url() or None,
                'banner': banner,
                'screenshots': [],
                'attachments': [],
                'release_thread': rel.release_thread,
                'videos': rel.videos,
                'notes': rel.notes,
                'first_release': mod.first_release.strftime('%Y-%m-%d'),
                'last_update': rel.last_update.strftime('%Y-%m-%d'),
                'cmdline': rel.cmdline,
                'mod_flag': rel.mod_flag,
                'type': mod.type,
                'packages': []
            }

            for prop in ('screenshots', 'attachments'):
                for chk in getattr(rel, prop):
                    if '://' in chk:
                        rmeta[prop].append(chk)
                    else:
                        image = files.get(chk)
                        if image:
                            rmeta[prop].append(image.get_url())

            for pkg in rel.packages:
                pmeta = {
                    'name': pkg.name,
                    'notes': pkg.notes,
                    'status': pkg.status,
                    'dependencies': [],
                    'environment': pkg.environment,
                    'folder': pkg.folder,
                    'is_vp': pkg.is_vp,
                    'executables': [],
                    'files': [],
                    'filelist': []
                }

                for dep in pkg.dependencies:
                    pmeta['dependencies'].append({
                        'id': dep.id,
                        'version': dep.version,
                        'packages': dep.packages
                    })

                for exe in pkg.executables:
                    pmeta['executables'].append({
                        'file': exe.file,
                        'label': exe.label
                    })

                vp_fix = {}
                for archive in pkg.files:
                    arfile = files.get(archive.checksum)
                    if arfile and arfile.duplicate_of:
                      rep = files[arfile.duplicate_of]
                      archive.checksum = rep.checksum
                      vp_fix[arfile.vp_checksum] = rep.vp_checksum
                      arfile = rep

                    file = {
                        'filename': archive.filename,
                        'dest': archive.dest,
                        'checksum': ('sha256', archive.checksum),
                        'filesize': archive.filesize,
                    }

                    if not archive.urls:
                        file['urls'] = arfile.get_urls()
                    else:
                        file['urls'] = archive.urls

                    pmeta['files'].append(file)

                if not no_chksum:
                    for file in pkg.filelist:
                        if file.checksum[1] in vp_fix:
                          file.checksum[1] = vp_fix[file.checksum[1]]

                        pmeta['filelist'].append({
                            'filename': file.filename,
                            'archive': file.archive,
                            'orig_name': file.orig_name,
                            'checksum': file.checksum
                        })

                rmeta['packages'].append(pmeta)
            repo.append(rmeta)

    return repo


def render_mod_list_minimal(mods):
    repo = []
    files = {}
    rel_map = {}

    fields = ('mod', 'version', 'stability', 'last_update')

    for rel in ModRelease.objects(hidden=False, private=False, mod__in=mods).only(*fields).select_related(4):
        rel_map.setdefault(rel.mod.id, []).append(rel)

    for mod in mods:
        if mod.tile:
            files[mod.tile] = None

    for item in UploadedFile.objects(checksum__in=files.keys()):
        files[item.checksum] = item

    missing = []
    for item in files.values():
      if item and item.duplicate_of and item.duplicate_of not in files:
        missing.append(item.duplicate_of)

    if missing:
      for item in UploadedFile.objects(checksum__in=missing):
        files[item.checksum] = item

    for mod in mods:
        tile = files.get(mod.tile)

        for rel in rel_map.get(mod.id, []):
            if rel.hidden or rel.private:
                continue

            rmeta = {
                'id': mod.mid,
                'title': mod.title,
                'version': rel.version,
                'stability': rel.stability if mod.type == 'engine' else None,
                'tile': tile and tile.get_url() or None,
                'first_release': mod.first_release.strftime('%Y-%m-%d'),
                'last_update': rel.last_update.strftime('%Y-%m-%d'),
                'type': mod.type,
            }

            repo.append(rmeta)

    return repo


def generate_repo():
    repo_min_path = os.path.join(app.config['FILE_STORAGE'], 'public', 'repo_minimal.json')
    lock_path = repo_min_path + '.lock'

    if os.path.isfile(lock_path):
        app.logger.error('Skipping repo update because another update is already in progress!')
        return

    open(lock_path, 'w').close()
    app.logger.info('Updating repo...')

    try:
        exclude_fields = ('members', 'team', 'releases')

        mods = Mod.objects.exclude(*exclude_fields).select_related(4)

        # minimal repo list
        repo = render_mod_list_minimal(mods)

        with open(repo_min_path, 'w') as stream:
            json.dump({'mods': repo}, stream)

    except Exception:
        app.logger.exception('Failed to update repository data!')

    # flag big repo as needing an update
    update_required = os.path.join(app.config['FILE_STORAGE'], 'repo_needs_update')
    open(update_required, 'w').close()

    app.logger.info('Repo update finished.')
    os.unlink(lock_path)


def generate_private_repo(mod):
    repo_path = os.path.join(app.config['FILE_STORAGE'], 'cache', 'mod_%s.json' % mod.id)
    app.logger.info('Updating mod %s repo...' % mod.mid)

    try:
        repo = render_mod_list([mod], private=True)
    
        with open(repo_path, 'w') as stream:
            json.dump(repo, stream)

        repo2_path = os.path.join(app.config['FILE_STORAGE'], 'cache', 'mod2_%s.json' % mod.id)
        repo = render_mod_list([mod], private=True, no_chksum=True)

        with open(repo2_path, 'w') as stream:
            json.dump(repo, stream)

    except Exception:
        app.logger.exception('Failed to update mod repository!')

    app.logger.info('Mod repo finished.')

