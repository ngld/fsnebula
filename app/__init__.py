import os.path
import logging
from flask import Flask
from werkzeug.middleware.shared_data import SharedDataMiddleware
from mongoengine import connect

__all__ = {'app'}

app = Flask(__name__)
app.config.from_envvar('NEBULA_SETTINGS')
app.logger.setLevel(logging.INFO)
connect(host=app.config['MONGO_DB'], connect=False)

from .controllers import user, mod, upload, log, static, track  # noqa

app.add_url_rule('/storage/<filename>', 'storage', build_only=True)
app.wsgi_app = SharedDataMiddleware(app.wsgi_app, {
    '/storage': os.path.join(app.config['FILE_STORAGE'], 'public')
})
