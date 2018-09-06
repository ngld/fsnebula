import re
import requests
from flask import render_template, abort, redirect

from .. import app


def fetch_kn_version():
    try:
        #resp = requests.get('https://github.com/ngld/knossos/releases')
        #m = re.search(r'<h1 class="release-title text-normal">\s*<a href="/ngld/knossos/releases/tag/v([0-9\.]+)">Knossos ', resp.text)
        resp = requests.get('https://api.github.com/repos/ngld/knossos/releases')
        # I'm too lazy to properly decode the response so let's keep using RegEx!
        m = re.search(r'"tag_name":\s*"v([0-9\.]+)",', resp.text)

        if not m:
            return False

        with open('version.txt', 'w') as stream:
            stream.write(m.group(1))
    except Exception:
        app.logger.exception('Failed to retrieve Knossos version!')
        return False
    else:
        return True


@app.route('/')
def index():
    return render_template('index.html.j2')


@app.route('/knossos/')
def show_knossos():
    return render_template('knossos.html.j2')


@app.route('/knossos/stable/version')
def get_kn_version():
    with open('version.txt', 'r') as stream:
        return stream.read()


@app.route('/knossos/stable/<base>.<ext>')
def knossos_dl(base, ext):
    if base == 'updater':
        base = 'update'

    if base not in ('Knossos', 'update') or ext not in ('exe', 'dmg'):
        abort(404)

    with open('version.txt', 'r') as stream:
        version = stream.read()

    url = 'https://github.com/ngld/knossos/releases/download/v%(version)s/%(base)s-%(version)s.%(ext)s' % {
        'base': base,
        'version': version,
        'ext': ext
    }
    return redirect(url)


@app.route('/knossos/release_update')
def knossos_update():
    if fetch_kn_version():
        return 'YES'
    else:
        return 'OH NO!'
