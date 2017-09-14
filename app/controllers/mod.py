import time
import os.path
import json
from flask import request, jsonify, abort

from .. import app
from ..helpers import verify_token
from ..models import User, Dependency, Executable, ModArchive, ModFile, Package, ModRelease, Mod, UploadedFile


@app.route('/api/1/mod/create', methods={'POST'})
def create_mod():
    user = verify_token()
    if not user:
        abort(403)

    form = request.form
    for field in ('id', 'title', 'type', 'folder', 'logo', 'tile', 'members'):
        if field not in form:
            abort(400)

    if not isinstance(form['members'], list):
        abort(400)

    mod = Mod(mid=form['id'],
              title=form['title'],
              type=form['type'],
              folder=form['folder'],
              first_release=time.time(),
              members=[user])

    if form['logo'] != '':
        logo = UploadedFile.objects(checksum=form['logo']).first()

        if logo:
            logo.make_permanent()
            mod.logo = logo.checksum

    if form['tile'] != '':
        tile = UploadedFile.objects(checksum=form['tile']).first()

        if tile:
            tile.make_permanent()
            mod.tile = tile.checksum

    for name in form['members']:
        member = User.objects(username=name).first()
        if member:
            mod.members.append(member)

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

    form = request.form
    for field in ('id', 'title', 'logo', 'tile', 'members'):
        if field not in form:
            abort(400)

    if not isinstance(form['members'], list):
        abort(400)

    mod = Mod.objects(mid=form['id']).first()
    if not mod:
        abort(404)

    if user not in mod.members:
        return jsonify(result=False, reason='unauthorized')

    mod.title = form['title']

    if mod.logo != form['logo']:
        logo = UploadedFile.objects(checksum=form['logo']).first()

        if logo:
            logo.make_permanent()
            mod.logo = logo.checksum

    if mod.tile != form['tile']:
        tile = UploadedFile.objects(checksum=form['tile']).first()

        if tile:
            tile.make_permanent()
            mod.tile = tile.checksum

    members = form['members']
    current = []
    for i, obj in enumerate(reversed(mod.members)):
        if obj.username not in members:
            del mod.members[i]
        else:
            current.append(obj.username)

    for name in members:
        if name not in current:
            obj = User.objects(username=name).first()

            if obj:
                mod.members.append(obj)

    mod.save()
    return jsonify(result=True)


@app.route('/api/1/mod/release', methods={'POST'})
def create_release():
    user = verify_token()
    if not user:
        abort(403)

    form = request.form
    for field in ('id',):
        if field not in form:
            abort(400)

    mod = Mod.objects(mid=form['id']).first()
    if not mod:
        abort(404)

    if user not in mod.members:
        return jsonify(result=False, reason='unauthorized')

    release = ModRelease(
        version=form['version'],
        description=form['description'],
        release_thread=form['release_thread'],
        videos=form['videos'],
        notes=form['notes'],
        last_update=time.time(),
        cmdline=form['cmdline'])

    files = []
    for pmeta in form['packages']:
        pkg = Package(
            name=pmeta['name'],
            notes=pmeta['notes'],
            status=pmeta['status'],
            environment=pmeta['environment'])

        for dmeta in pmeta['dependencies']:
            dep = Dependency(id=dmeta['id'], version=dmeta['version'], packages=dmeta['packages'])
            pkg.dependencies.append(dep)

        for emeta in pmeta['executables']:
            exe = Executable(file=emeta['file'], debug=emeta['debug'])
            pkg.executables.append(exe)

        for ameta in pmeta['files']:
            if ameta['checksum'][0] != 'sha256':
                return jsonify(result=False, reason='unsupported archive checksum')

            archive = ModArchive(filename=ameta['filename'],
                                 dest=ameta['dest'],
                                 checksum=ameta['checksum'][1],
                                 filesize=ameta['filesize'])

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
    mod.save()

    for file in files:
        if not file.mod:
            file.mod = mod

        file.make_permanent()

    generate_repo()
    return jsonify(result=True)


def generate_repo():
    repo_path = os.path.join(app.config['FILE_STORAGE'], 'public', 'repo.json')
    lock_path = repo_path + '.lock'

    if os.path.isfile(lock_path):
        app.logger.error('Skipping repo update because another update is already in progress!')
        return

    open(lock_path, 'w').close()
    app.logger.info('Updating repo...')

    repo = []
    for mod in Mod.objects:
        for rel in mod.releases:
            if rel.hidden:
                continue

            logo = UploadedFile.objects(checksum=rel.logo).first()
            tile = UploadedFile.objects(checksum=rel.tile).first()

            rmeta = {
                'id': mod.mid,
                'title': mod.title,
                'version': rel.version,
                'description': rel.description,
                'logo': logo and logo.get_url() or None,
                'tile': tile and tile.get_url() or None,
                'release_thread': rel.release_thread,
                'videos': rel.videos,
                'notes': rel.notes,
                'folder': mod.folder,
                'first_release': mod.first_release,
                'last_update': None,
                'cmdline': rel.cmdline,
                'type': mod.type,
                'packages': []
            }

            for pkg in rel.packages:
                pmeta = {
                    'name': pkg.name,
                    'notes': pkg.notes,
                    'status': pkg.status,
                    'dependencies': [],
                    'environment': pkg.environment,
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
                        'debug': exe.debug
                    })

                for archive in pkg.files:
                    arfile = UploadedFile.objects(checksum=archive.checksum).first()

                    pmeta['files'].append({
                        'filename': archive.filename,
                        'dest': archive.dest,
                        'checksum': ('sha256', archive.checksum),
                        'filesize': archive.filesize,
                        'urls': [arfile.get_url()]
                    })

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
        json.dump(stream, {'mods': repo})

    app.logger.info('Repo update finished.')
    os.unlink(lock_path)
