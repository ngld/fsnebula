import time
import smtplib
import hashlib
import jwt

from passlib.hash import argon2
from flask import request, abort
from . import app
from .models import User


def hash_password(value):
    return argon2.using(rounds=app.config['ARGON2_ROUNDS']).hash(value)


def verify_password(value, hash):
    return argon2.verify(value, hash)


def generate_token(uid):
    return jwt.encode({
        'uid': uid,
        'exp': time.time() + app.config['TOKEN_LIFETIME']
    }, app.config['JWT_SECRET']).decode('utf8')


def verify_token(token=None):
    if not token:
        token = request.headers.get('X-KN-TOKEN')

    try:
        pay = jwt.decode(token, app.config['JWT_SECRET'])
    except jwt.ExpiredSignature:
        abort(401)
    except jwt.DecodeError:
        abort(403)

    user = User.objects(username=pay['uid']).first()
    if not user or not user.active:
        abort(403)

    return user


def send_mail(msg):
    if app.config['SMTP_SSL']:
        smtp = smtplib.SMTP_SSL(app.config['SMTP_HOST'], app.config['SMTP_PORT'])
    else:
        smtp = smtplib.SMTP(app.config['SMTP_HOST'], app.config['SMTP_PORT'])

        if app.config['SMTP_STARTTLS']:
            smtp.starttls()

    if app.config['SMTP_USER'] is not None:
        smtp.login(app.config['SMTP_USER'], app.config['SMTP_PASSWORD'])

    if msg['From'] is None:
        msg['From'] = app.config['MAIL_SENDER']

    smtp.send_message(msg)
    smtp.quit()


def gen_hash(stream, algo='md5'):
    h = hashlib.new(algo)
    chunk = stream.read(16 * h.block_size)

    while chunk:
        h.update(chunk)
        chunk = stream.read(16 * h.block_size)

    return h.hexdigest()
