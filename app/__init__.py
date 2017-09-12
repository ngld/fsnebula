from flask import Flask
from mongoengine import connect

__all__ = {'app'}

app = Flask(__name__)
app.config.from_envvar('NEBULA_SETTINGS')
connect(host=app.config['MONGO_DB'])

from .controllers import user  # noqa
