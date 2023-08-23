from flask import request

from .. import app

@app.route('/api/1/track', methods={'POST'})
def track_event():
    ev = request.form.get('event', '')
    counter = request.form.get('counter', '')

    if ev == 'download':
        app.logger.warning('TRACK: Download %s took %s seconds.' % (request.form.get('link', '???'), request.form.get('time', '???')))
    elif counter == 'install_mod':
        app.logger.warning('TRACK: Mod %s %s installed (dependency = %s)' % (request.form.get('mid', '???'), request.form.get('version', '???'), request.form.get('dependency', '???')))
    elif counter == 'uninstall_mod':
        app.logger.warning('TRACK: Mod %s %s UNinstalled (dependency = %s)' % (request.form.get('mid', '???'), request.form.get('version', '???'), request.form.get('dependency', '???')))
    else:
        app.logger.warning('TRACK: Mystery! (%s, %s)' % (ev, counter))

    return 'OK'
