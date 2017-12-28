import os.path
import json
import semantic_version
import requests
from datetime import datetime
from email.message import EmailMessage
from flask import request, jsonify, abort, url_for, redirect, render_template
from mongoengine.errors import ValidationError

from .. import app
from ..helpers import verify_token, send_mail
from ..models import Dependency, Executable, ModArchive, ModFile, Package, ModRelease, Mod, UploadedFile


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
              members=[user])

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

    if user not in mod.members:
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
                  members=[user])
    else:
        if user not in mod.members:
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

    if user not in mod.members:
        return meta, mod, None, user, 'unauthorized'

    release = ModRelease(
        version=meta['version'],
        description=meta.get('description', ''),
        release_thread=meta.get('release_thread', None),
        videos=meta.get('videos', []),
        notes=meta.get('notes', ''),
        last_update=datetime.now(),
        cmdline=meta.get('cmdline', ''),
        mod_flag=meta.get('mod_flag', ''))

    if mod.type == 'engine':
        release.stability = meta.get('stability', 'stable')

    try:
        new_ver = semantic_version.Version(meta['version'])
    except ValueError:
        app.logger.exception('Invalid version "%s" provided during preflight check!' % meta['version'])
        return meta, mod, None, user, 'invalid version'

    if not ignore_duplicate:
        for rel in mod.releases:
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


@app.route('/api/1/mod/release', methods={'POST'})
def create_release():
    meta, mod, release, user, error = _do_preflight(save=True)
    if error:
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

        for ameta in pmeta['files']:
            if ameta['checksum'][0] != 'sha256':
                return jsonify(result=False, reason='unsupported archive checksum')

            archive = ModArchive(filename=ameta['filename'],
                                 dest=ameta['dest'],
                                 checksum=ameta['checksum'][1],
                                 filesize=ameta['filesize'])

            if 'urls' in ameta:
                if user.username not in app.config['URLS_FOR']:
                    return jsonify(result=False, reason='urls unauthorized')

                archive.urls = ameta['urls']
            else:
                file = UploadedFile.objects(checksum=archive.checksum).first()
                if not file:
                    return jsonify(result=False, reason='archive missing', archive=ameta['filename'])

                files.append(file)

            pkg.files.append(archive)

        for fmeta in pmeta['filelist']:
            file = ModFile(filename=fmeta['filename'],
                           archive=fmeta['archive'],
                           orig_name=fmeta['orig_name'],
                           checksum=fmeta['checksum'])

            pkg.filelist.append(file)

        release.packages.append(pkg)

    mod.releases.append(release)
    try:
        mod.save()
    except ValidationError as exc:
        return jsonify(result=False, reason=str(exc))

    for file in files:
        if not file.mod:
            file.mod = mod

        file.make_permanent()

    generate_repo()

    if app.config['DISCORD_WEBHOOK']:
        try:
            img = release.banner or mod.logo
            if img:
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
                'avatar_url': url_for('static', filename='avatar.png', _external=True),
                'embeds': [{
                    'url': url_for('view_mod', mid=mod.mid, _external=True),
                    'title': '%s %s %s released!' % (type_names.get(mod.type, ''), mod.title, release.version),
                    'image': img
                }]
            })
        except Exception:
            app.logger.exception('Failed to execute Discord webhook!')

    return jsonify(result=True)


@app.route('/api/1/mod/release/update', methods={'POST'})
def update_release():
    meta, mod, release, user, error = _do_preflight(save=True, ignore_duplicate=True)
    if error:
        return jsonify(result=False, reason=error)

    old_rel = None
    idx = -1
    for i, rel in enumerate(mod.releases):
        if rel.version == release.version:
            old_rel = rel
            idx = i
            break

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
    mod.releases[idx] = release
    mod.save()

    generate_repo()
    return jsonify(result=True)


@app.route('/api/1/mod/release/delete', methods={'POST'})
def delete_release():
    user = verify_token()
    if not user:
        abort(403)

    mod = Mod.objects(mid=request.form['mid']).first()
    if not mod:
        abort(404)

    if user not in mod.members:
        return jsonify(result=False, reason='unauthorized')

    version = request.form['version']
    release = None
    for rel in mod.releases:
        if rel.version == version:
            release = rel
            break

    if not release:
        abort(404)

    release.hidden = True
    release.save()

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
    release = None
    for rel in mod.releases:
        if rel.version == version:
            release = rel
            break

    if not release:
        abort(404)

    msg = EmailMessage()
    msg['To'] = app.config['ADMIN_MAIL']
    msg['Subject'] = 'FSNebula Abuse Report - %s %s' % (mod.title, version)
    msg.set_content('User: %s\nMessage:\n%s' % (user.username, request.form['message']))
    send_mail(msg)

    return jsonify(result=True)


@app.route('/api/1/mod/editable', methods={'GET'})
def get_editable_mods():
    user = verify_token()
    if not user:
        abort(403)

    mods = [mod.mid for mod in Mod.objects(members=user.username)]
    return jsonify(result=True, mods=mods)


@app.route('/api/1/mod/rebuild_repo', methods={'GET'})
def rebuild_repo():
    # TODO Access check
    generate_repo()

    return jsonify(result=True)


@app.route('/mod/<mid>', methods={'GET'})
def view_mod(mid):
    mod = Mod.objects(mid=mid).first()
    if not mod or len(mod.releases) < 0:
        abort(404)

    rel = mod.releases[-1]
    banner = None

    if rel.banner:
        b = UploadedFile.objects(checksum=rel.banner).first()
        if b:
            banner = b.get_url()

    return render_template('mod_install.html.j2', mod={
        'id': mod.mid,
        'title': mod.title,
        'version': rel.version,
        'banner': banner
    })


def generate_repo():
    repo_path = os.path.join(app.config['FILE_STORAGE'], 'public', 'repo.json')
    lock_path = repo_path + '.lock'

    if os.path.isfile(lock_path):
        app.logger.error('Skipping repo update because another update is already in progress!')
        return

    open(lock_path, 'w').close()
    app.logger.info('Updating repo...')

    try:
        repo = []
        for mod in Mod.objects:
            logo = UploadedFile.objects(checksum=mod.logo).first()
            tile = UploadedFile.objects(checksum=mod.tile).first()

            for rel in mod.releases:
                if rel.hidden:
                    continue

                if rel.banner and '://' in rel.banner:
                    banner = rel.banner
                else:
                    banner = UploadedFile.objects(checksum=rel.banner).first()
                    if banner:
                        banner = banner.get_url()

                rmeta = {
                    'id': mod.mid,
                    'title': mod.title,
                    'version': rel.version,
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
                            image = UploadedFile.objects(checksum=chk).first()
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

                    for archive in pkg.files:
                        file = {
                            'filename': archive.filename,
                            'dest': archive.dest,
                            'checksum': ('sha256', archive.checksum),
                            'filesize': archive.filesize,
                        }

                        if not archive.urls:
                            arfile = UploadedFile.objects(checksum=archive.checksum).first()
                            file['urls'] = [arfile.get_url()]
                        else:
                            file['urls'] = archive.urls

                        pmeta['files'].append(file)

                    for file in pkg.filelist:
                        pmeta['filelist'].append({
                            'filename': file.filename,
                            'archive': file.archive,
                            'orig_name': file.orig_name,
                            'checksum': file.checksum
                        })

                    rmeta['packages'].append(pmeta)

                repo.append(rmeta)

        with open(repo_path, 'w') as stream:
            json.dump({'mods': repo}, stream)

    except Exception:
        app.logger.exception('Failed to update repository data!')

    app.logger.info('Repo update finished.')
    os.unlink(lock_path)
