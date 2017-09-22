from email.message import EmailMessage
from secrets import token_urlsafe
from flask import request, jsonify, render_template, url_for, abort
from mongoengine.errors import NotUniqueError

from .. import app
from ..models import User
from ..helpers import (
    hash_password, verify_password, generate_token, verify_token, send_mail
)


# TODO: Prevent abuse (spamming someone with registration mails)
@app.route('/api/1/register', methods={'POST'})
def register():
    user = User(
        username=request.form['name'],
        email=request.form['email'],
        password=hash_password(request.form['password']),
        register_token=token_urlsafe(30)
    )

    try:
        user.save(True)
    except NotUniqueError:
        return jsonify(result=False, reason='already registered')

    msg = EmailMessage()
    msg['To'] = user.email
    msg['Subject'] = 'Confirm your registration on fsnebula.org'
    msg.set_content(render_template('mail/register.txt',
        username=user.username,
        link=url_for('confirm_register', username=user.username, token=user.register_token, _external=True)
    ))
    send_mail(msg)

    return jsonify(result=True)


@app.route('/confirm/<username>/<token>')
def confirm_register(username, token):
    user = User.objects(username=username).first()
    if not user or user.register_token != token:
        abort(404)

    user.register_token = None
    user.active = True
    user.save()

    return 'Success!'


@app.route('/recover/<username>/<token>', methods={'GET', 'POST'})
def recover_password(username, token):
    user = User.objects(username=username).first()
    if not user or user.reset_token != token:
        abort(404)

    msg = None
    if 'new_password' in request.form:
        if request.form['new_password'] != request.form['confirm']:
            msg = "The passwords don't match!"
        elif len(request.form['new_password']) < 5:
            msg = "The password needs to be at least 5 characters long."
        else:
            user.reset_token = None
            user.register_token = None
            user.active = True
            user.password = hash_password(request.form['new_password'])
            user.save()

            return render_template('reset.html', success=True)

    return render_template('reset.html', success=False, msg=msg)


@app.route('/api/1/reset_password', methods={'POST'})
def reset_password():
    user = User.objects(username=request.form.get('user')).first()
    if not user:
        abort(404)

    user.reset_token = token_urlsafe(30)
    user.save()

    msg = EmailMessage()
    msg['To'] = user.email
    msg['Subject'] = 'FSNebula - Password reset'
    msg.set_content(render_template('mail/reset.txt',
        username=user.username,
        link=url_for('recover_password', username=user.username, token=user.reset_token, _external=True)
    ))
    send_mail(msg)

    return jsonify(result=True)


@app.route('/api/1/login', methods={'POST'})
def login():
    user = User.objects(username=request.form.get('user')).first()
    if not user or not user.active or not verify_password(request.form.get('password'), user.password):
        return jsonify(result=False)

    return jsonify(
        result=True,
        token=generate_token(user.username)
    )


@app.route('/api/1/change_password', methods={'POST'})
def change_password():
    user = verify_token()
    if not user:
        abort(403)

    user.password = hash_password(request.form['password'])
    user.save()

    return jsonify(result=True)


@app.route('/api/1/list_users', methods={'GET'})
def get_users():
    user = verify_token()
    if not user:
        abort(403)

    return jsonify(result=True, list=[o.username for o in User.objects(active=True)])
