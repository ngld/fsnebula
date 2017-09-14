import os.path
from flask import Flask
from werkzeug.wsgi import SharedDataMiddleware
from mongoengine import connect

__all__ = {'app'}

app = Flask(__name__)
app.config.from_envvar('NEBULA_SETTINGS')
connect(host=app.config['MONGO_DB'])

from .controllers import user  # noqa

app.add_url_rule('/storage/<filename>', 'storage', build_only=True)
app.wsgi_app = SharedDataMiddleware(app.wsgi_app, {
    '/storage': os.path.join(app.config['FILE_STORAGE'], 'public')
})
