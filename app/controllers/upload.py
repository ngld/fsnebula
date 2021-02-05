import os.path
import time
import re
import hashlib
import shutil
import magic
from io import SEEK_END
from flask import request, jsonify, abort

from .. import app
from ..helpers import verify_token, gen_hash
from ..models import UploadedFile, ChunkedUpload


HEX_RE = re.compile(r'^[0-9a-f]+$')


@app.route('/api/1/upload/check', methods={'POST'})
def check_uploaded():
    user = verify_token()
    if not user:
        abort(403)

    if 'content_checksum' in request.form:
        if 'is_vp' not in request.form:
            return jsonify(result=False)

        cond = {'content_checksum': request.form['content_checksum'], 'duplicate_of': None, 'is_vp': request.form['is_vp']}

        #if request.form['is_vp']:
        #    cond['vp_checksum__ne'] = None
        #else:
        #    cond['vp_checksum'] = None

        file = UploadedFile.objects(**cond).first()
    else:
        file = UploadedFile.objects(checksum=request.form['checksum']).first()

    if file:
        return jsonify(result=True, checksum=file.checksum, filesize=file.filesize, vp_checksum=file.vp_checksum, is_vp=file.is_vp)
    else:
        return jsonify(result=False)


@app.route('/api/1/upload/check_archive', methods={'POST'})
def check_uploaded_archive():
    user = verify_token()
    if not user:
        abort(403)

    #if 


@app.route('/api/1/upload/file', methods={'POST'})
def upload_file():
    user = verify_token()
    if not user:
        abort(403)

    if 'checksum' not in request.form or 'file' not in request.files:
        abort(400)

    file = request.files['file']
    checksum = request.form['checksum']
    if gen_hash(file.stream, 'sha256') != checksum:
        return jsonify(result=False, reason='checksum')

    file.seek(0)
    mime = magic.from_buffer(file.read(1024), mime=True)
    if mime in app.config['MIME_BLACKLIST']:
        return jsonify(result=False, reason='invalid mime')

    file.seek(0, SEEK_END)
    record = UploadedFile(expires=time.time() + 24 * 60 * 60,
                          checksum=checksum,
                          content_checksum=request.form.get('content_checksum'),
                          vp_checksum=request.form.get('vp_checksum'),
                          filesize=file.tell())

    if mime in ('image/jpg', 'image/jpeg'):
        record.file_ext = 'jpg'
    elif mime == 'image/png':
        record.file_ext = 'png'
    elif mime == 'image/x-ms-bmp':
        record.file_ext = 'bmp'

    # currently broken
    if False:  # record.content_checksum:
        duplicate = UploadedFile.objects(content_checksum=record.content_checksum, vp_checksum__ne=None, duplicate_of=None).first()
        if duplicate:
            record.duplicate_of = duplicate.checksum
            app.logger.warning('UploadedFile %s is a duplicate of %s!' % (record.checksum, duplicate.checksum))

    record.gen_filename()
    record.save()

    full_path = os.path.join(app.config['FILE_STORAGE'], os.path.normpath(record.filename))
    os.makedirs(os.path.dirname(full_path), exist_ok=True)

    file.seek(0)
    file.save(full_path)

    return jsonify(result=True)


@app.route('/api/1/multiupload/start', methods={'POST'})
def start_chunked_upload():
    user = verify_token()
    if not user:
        abort(403)

    if not HEX_RE.fullmatch(request.form['id']):
        abort(400)

    file = ChunkedUpload.objects(id=request.form['id']).first()
    if not file:
        file = ChunkedUpload(
                id=request.form['id'],
                filesize=int(request.form['size']),
                total_parts=int(request.form['parts']),
                expires=time.time() + 24 * 60 * 60)
        file.save()
        
    chunk_path = os.path.join(app.config['FILE_STORAGE'], 'chunks', file.id)
    os.makedirs(chunk_path, exist_ok=True)

    return jsonify(
            result=True,
            done=file.done,
            finished_parts=file.finished_parts)

@app.route('/api/1/multiupload/finish', methods={'POST'})
def finish_chunked_upload():
    user = verify_token()
    if not user:
        abort(403)

    file = ChunkedUpload.objects(id=request.form['id']).first()
    if not file:
        abort(404)

    record = UploadedFile(expires=time.time() + 60 * 60,
                          checksum=request.form['checksum'],
                          content_checksum=request.form.get('content_checksum'),
                          vp_checksum=request.form.get('vp_checksum'),
                          filesize=file.filesize)

    record.gen_filename()
    record.save()

    full_path = os.path.join(app.config['FILE_STORAGE'], os.path.normpath(record.filename))
    chunk_path = os.path.join(app.config['FILE_STORAGE'], 'chunks', file.id)

    os.makedirs(os.path.dirname(full_path), exist_ok=True)

    h = hashlib.new('sha256')
    failed = False
    try:
        with open(full_path, 'wb') as hdl:
            for num in range(file.total_parts):
                cp = os.path.join(chunk_path, str(num))

                with open(cp, 'rb') as chunk:
                    while True:
                        data = chunk.read(1024 * 1024)
                        if not data:
                            break
                        
                        h.update(data)
                        hdl.write(data)
    except Exception:
        app.logger.exception('Failed to join chunks for file %s!' % file.id)
        os.unlink(full_path)
        record.delete()
        abort(500)

    if h.hexdigest() != record.checksum:
        os.unlink(full_path)
        record.delete()
        return jsonify(result=False, reason='checksum fail')
    
    record.make_permanent()
    file.done = True
    file.save()

    try:
        shutil.rmtree(chunk_path)
    except Exception:
        app.logger.exception('Failed to cleanup chunk directory for upload %s!' % file.id)

    return jsonify(result=True)


@app.route('/api/1/multiupload/part', methods={'POST'})
def upload_chunk():
    user = verify_token()
    if not user:
        abort(403)

    file = ChunkedUpload.objects(id=request.form['id']).first()
    if not file:
        abort(404)

    part = request.files['file']
    idx = int(request.form['part'])
    chunk_path = os.path.join(app.config['FILE_STORAGE'], 'chunks', file.id, str(idx))

    part.save(chunk_path)
    return 'OK'

@app.route('/api/1/multiupload/verify_part', methods={'POST'})
def verify_chunk():
    user = verify_token()
    if not user:
        abort(403)

    file = ChunkedUpload.objects(id=request.form['id']).first()
    if not file:
        abort(404)

    idx = int(request.form['part'])
    chunk_path = os.path.join(app.config['FILE_STORAGE'], 'chunks', file.id, str(idx))
    checksum = request.form['checksum']

    with open(chunk_path, 'rb') as hdl:
        if gen_hash(hdl, 'sha256') != checksum:
            return jsonify(result=False, reason='checksum')

    ChunkedUpload.objects(id=request.form['id']).update_one(push__finished_parts=idx)
    return jsonify(result=True)

