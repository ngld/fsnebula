import pygments.formatters
from datetime import datetime
from flask import request, jsonify, abort, render_template, url_for

from .. import app
from ..helpers import verify_token
from ..models import Log
from ..log_lexer import FsoLogLexer


@app.route('/api/1/log/upload', methods={'POST'})
def upload_log():
    user = verify_token()
    if not user:
        abort(403)

    try:
        log = Log(content=request.form['log'], uploaded=datetime.now())
        log.save()
    except Exception:
        app.logger.exception('Failed to store log!')
        return jsonify(result=False)
    else:
        return jsonify(result=True, id=str(log.id))


@app.route('/log/<log_id>', methods={'GET'})
def view_log(log_id):
    log = Log.objects(id=log_id).first()
    if not log:
        abort(404)

    lexer = FsoLogLexer()
    formatter = pygments.formatters.get_formatter_by_name('html',
        linenos='table', lineanchors=True, anchorlinenos=True)
    content = pygments.highlight(log.content, lexer, formatter)

    return render_template('log.html', uploaded=log.uploaded, content=content, css=formatter.get_style_defs())


@app.route('/log/search', methods={'GET', 'POST'})
def search_logs():
    results = []

    if 'query' in request.form:
        query = request.form['query']
        for item in Log.objects.search_text(query):
            index = item.content.find(query)

            # build a clamped window around the found position
            start = max(0, index - 200)
            end = min(index + 200, len(item.content))

            # clamp the start and end to linebreaks
            start = item.content.find('\n', start, end)
            end = item.content.rfind('\n', start, end)

            results.append({
                'link': url_for('view_log', log_id=item.id),
                'uploaded': item.uploaded,
                'teaser': item.content[start:end]
            })

    return render_template('log_search.html', results=results)
