import os.path
import time
import re
import shutil
import stat
import tempfile
from contextlib import contextmanager, suppress
from fcntl import flock, LOCK_EX, LOCK_NB
import magic
from io import SEEK_END
from flask import request, jsonify, abort

from .. import app
from ..helpers import verify_token, gen_hash
from ..models import UploadedFile, ChunkedUpload


HEX_RE = re.compile(r'[0-9a-f]{1,128}')
SHA256_RE = re.compile(r'[0-9a-f]{64}')


def _upload_id():
    upload_id = request.form['id']
    if not HEX_RE.fullmatch(upload_id):
        abort(400)
    return upload_id


@contextmanager
def _storage_lock(path, wait):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # Keep the lock file so concurrent workers always lock the same inode.
    # Closing the descriptor (including on worker exit) releases the lock.
    with open(path, 'a+b') as lock:
        try:
            flock(lock, LOCK_EX if wait else LOCK_EX | LOCK_NB)
        except BlockingIOError:
            yield None
        else:
            yield lock


def _upload_lock(upload_id, wait=True):
    # The upload ID may differ from the checksum. Always lock the session first.
    path = os.path.join(app.config['FILE_STORAGE'], 'upload-locks', 'sessions', upload_id)
    return _storage_lock(path, wait)


def _checksum_lock_path(checksum):
    return os.path.join(app.config['FILE_STORAGE'], 'upload-locks', checksum[:2], checksum[2:])


def _checksum_lock(checksum, wait=True):
    return _storage_lock(_checksum_lock_path(checksum), wait)


def _chunk_dir(upload_id):
    return os.path.join(app.config['FILE_STORAGE'], 'chunks', upload_id)


def _get_upload(upload_id):
    upload = ChunkedUpload.objects(id=upload_id).first()
    if upload is None:
        abort(404)
    return upload


def _fingerprint(info):
    return '%s:%s:%s' % (info.st_ino, info.st_mtime_ns, info.st_ctime_ns)


def _read_lock_value(lock):
    lock.seek(0)
    return lock.read(128).decode('ascii', errors='ignore')


def _write_lock_value(lock, value):
    # Keep the cache on disk so old MongoEngine models can still read every record.
    lock.seek(0)
    lock.truncate()
    lock.write(value.encode('ascii'))
    lock.flush()


def _saved_checksum(lock):
    checksum = _read_lock_value(lock)
    return checksum if SHA256_RE.fullmatch(checksum) else None


def _verified_file(path, size, checksum, verified=None):
    try:
        info = os.stat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size != size:
            return None
        fingerprint = _fingerprint(info)
        # An unchanged file has already passed the full SHA-256 check.
        if fingerprint == verified:
            return fingerprint
        with open(path, 'rb') as stream:
            if gen_hash(stream, 'sha256', read_size=1024 * 1024) == checksum:
                if _fingerprint(os.stat(path)) == fingerprint:
                    return fingerprint
    except FileNotFoundError:
        pass
    return None


def _published_record(checksum, size, lock, metadata=None):
    record = UploadedFile.objects(checksum=checksum).first()
    if record and record.expires == -1 and record.storage == 'cold':
        # A cold object is served by its configured remote mirror.
        return record if record.filesize == size else None

    needs_save = record is None or record.expires != -1 or record.filesize != size
    if record is None:
        record = UploadedFile(checksum=checksum, expires=-1, filesize=size)
        if metadata is not None:
            record.content_checksum = metadata.get('content_checksum')
            record.vp_checksum = metadata.get('vp_checksum')
        record.gen_filename()
    elif record.expires != -1:
        record.expires = -1
        record.gen_filename()

    path = os.path.join(app.config['FILE_STORAGE'], record.filename)
    cached = _read_lock_value(lock)
    verified = _verified_file(path, size, checksum, cached)
    if verified is None:
        return None

    if needs_save:
        record.filesize = size
        record.save()
    if verified != cached:
        _write_lock_value(lock, verified)
    return record


def _set_upload_done(upload):
    if not upload.done:
        upload.done = True
        upload.save()

    try:
        shutil.rmtree(_chunk_dir(upload.id))
    except FileNotFoundError:
        pass
    except OSError:
        app.logger.exception('Failed to clean up chunks for upload %s', upload.id)


def _reset_lost_upload(upload):
    if upload.done:
        app.logger.error('Multipart upload %s was marked complete but has no valid published file', upload.id)
        upload.done = False
        upload.finished_parts = []
        upload.save()


def checked_upload_record(record):
    if not record or not SHA256_RE.fullmatch(record.checksum):
        return record
    checksum = record.checksum
    upload = ChunkedUpload.objects(id=checksum).first()
    if upload or os.path.isfile(_checksum_lock_path(checksum)):
        with _checksum_lock(checksum) as lock:
            if upload or _read_lock_value(lock):
                size = upload.filesize if upload else record.filesize
                return _published_record(checksum, size, lock)
    return record


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

    file = checked_upload_record(file)
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
    record.validate()
    with _checksum_lock(checksum) as lock:
        existing = UploadedFile.objects(checksum=checksum).first()
        if existing and existing.expires == -1:
            if existing.storage == 'cold':
                return jsonify(result=True)
            record = existing
            record.filesize = file.tell()

        full_path = os.path.join(app.config['FILE_STORAGE'], record.filename)
        if _verified_file(full_path, record.filesize, checksum, _read_lock_value(lock)) is None:
            temp_dir = os.path.join(app.config['FILE_STORAGE'], 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with tempfile.TemporaryDirectory(dir=temp_dir) as work_dir:
                source = os.path.join(work_dir, 'file')
                file.seek(0)
                file.save(source)
                os.replace(source, full_path)
        if record.expires == -1:
            record.save()
        elif not record.save_unless_permanent():
            # A release may have promoted the record while this request wrote the file.
            with suppress(FileNotFoundError):
                os.unlink(full_path)

    return jsonify(result=True)


@app.route('/api/1/multiupload/start', methods={'POST'})
def start_chunked_upload():
    user = verify_token()
    if not user:
        abort(403)

    upload_id = _upload_id()
    size = request.form.get('size', type=int)
    parts = request.form.get('parts', type=int)
    if size is None or size < 0 or parts is None or parts < 0 or bool(size) != bool(parts):
        abort(400)

    with _upload_lock(upload_id, wait=False) as lock:
        if lock:
            return _start_upload(upload_id, size, parts, lock)
        upload = ChunkedUpload.objects(id=upload_id).first()
        if upload:
            return jsonify(result=True, done=False, finished_parts=upload.finished_parts)

    # Two first-time start requests may arrive before either has registered the upload.
    with _upload_lock(upload_id) as lock:
        return _start_upload(upload_id, size, parts, lock)


def _start_upload(upload_id, size, parts, session_lock):
    upload = ChunkedUpload.objects(id=upload_id).first()
    if upload is None:
        # The database record may have expired while its lock file remained.
        _write_lock_value(session_lock, '')
        upload = ChunkedUpload(id=upload_id, filesize=size, total_parts=parts,
                               expires=time.time() + 24 * 60 * 60)
        upload.save()
    if upload.filesize != size:
        return jsonify(result=False, done=False, reason='upload size mismatch')

    saved_checksum = _saved_checksum(session_lock)
    checksum = saved_checksum or upload_id
    if SHA256_RE.fullmatch(checksum):
        with _checksum_lock(checksum, wait=False) as lock:
            if not lock:
                return jsonify(result=True, done=False, finished_parts=upload.finished_parts)
            if _published_record(checksum, size, lock):
                if not saved_checksum:
                    _write_lock_value(session_lock, checksum)
                _set_upload_done(upload)
                return jsonify(result=True, done=True, finished_parts=upload.finished_parts)

    _reset_lost_upload(upload)
    if upload.total_parts != parts:
        return jsonify(result=False, done=False, reason='upload part count mismatch')

    chunk_dir = _chunk_dir(upload_id)
    os.makedirs(chunk_dir, exist_ok=True)
    available = [part for part in upload.finished_parts
                 if os.path.isfile(os.path.join(chunk_dir, str(part)))]
    if available != upload.finished_parts:
        upload.finished_parts = available
        upload.save()
    return jsonify(result=True, done=False, finished_parts=available)

@app.route('/api/1/multiupload/finish', methods={'POST'})
def finish_chunked_upload():
    user = verify_token()
    if not user:
        abort(403)

    checksum = request.form['checksum']
    if not SHA256_RE.fullmatch(checksum):
        abort(400)
    upload_id = _upload_id()

    with _upload_lock(upload_id, wait=False) as session_lock:
        if session_lock:
            upload = _get_upload(upload_id)
            with _checksum_lock(checksum, wait=False) as lock:
                if lock:
                    return _finish_upload(upload, checksum, session_lock, lock)

    # Knossos 1.3 treats this as a missing finish reply and polls start.
    return jsonify(result=False, reason='upload busy'), 503, {'Retry-After': '2'}


def _finish_upload(upload, checksum, session_lock, lock):
    saved_checksum = _saved_checksum(session_lock)
    if saved_checksum and saved_checksum != checksum:
        return jsonify(result=False, reason='checksum fail')

    # Unbound legacy IDs must still prove the bytes in their own chunks.
    can_resume = checksum == upload.id or saved_checksum is not None or upload.done
    if not can_resume or _published_record(checksum, upload.filesize, lock, request.form) is None:
        _reset_lost_upload(upload)
        error = _assemble_upload(upload, checksum, request.form, lock, check_published=not can_resume)
        if error:
            return jsonify(result=False, reason=error)

    if not saved_checksum:
        _write_lock_value(session_lock, checksum)
    _set_upload_done(upload)
    app.logger.info('Finished upload for %s', upload.id)
    return jsonify(result=True)


def _assemble_upload(upload, checksum, metadata, lock, check_published):
    chunk_dir = _chunk_dir(upload.id)
    os.makedirs(chunk_dir, exist_ok=True)
    # Remove temporary files left behind if the previous worker died.
    cutoff = time.time() - 60 * 60
    for name in os.listdir(chunk_dir):
        path = os.path.join(chunk_dir, name)
        if name.startswith(('assembly-', 'part-')):
            shutil.rmtree(path)
        elif name.startswith('joined-'):
            with suppress(OSError):
                if os.path.getmtime(path) < cutoff:
                    os.unlink(path)

    record = UploadedFile.objects(checksum=checksum).first()
    if record is None:
        record = UploadedFile(checksum=checksum)
    if record.expires != -1:
        record.expires = -1
        record.gen_filename()
    record.filesize = upload.filesize
    record.content_checksum = metadata.get('content_checksum') or record.content_checksum
    record.vp_checksum = metadata.get('vp_checksum') or record.vp_checksum
    record.storage = None
    record.validate()

    with tempfile.TemporaryDirectory(prefix='assembly-', dir=chunk_dir) as work_dir:
        source = os.path.join(work_dir, 'file')
        with open(source, 'wb') as output:
            for part in range(upload.total_parts):
                try:
                    chunk = open(os.path.join(chunk_dir, str(part)), 'rb')
                except FileNotFoundError:
                    upload.update(pull__finished_parts=part)
                    return 'part missing'
                with chunk:
                    shutil.copyfileobj(chunk, output, 1024 * 1024)

        if _verified_file(source, upload.filesize, checksum) is None:
            upload.update(set__finished_parts=[])
            return 'checksum fail'

        if check_published and _published_record(checksum, upload.filesize, lock):
            return None

        # Publish only closed, verified bytes, in one rename on FILE_STORAGE.
        dest = os.path.join(app.config['FILE_STORAGE'], record.filename)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        os.replace(source, dest)
        record.save()
        _write_lock_value(lock, _fingerprint(os.stat(dest)))


@app.route('/api/1/multiupload/part', methods={'POST'})
def upload_chunk():
    user = verify_token()
    if not user:
        abort(403)

    upload_id = _upload_id()
    part = request.files['file']
    with _upload_lock(upload_id):
        upload = _get_upload(upload_id)
        idx = _part_index(upload)
        if not upload.done:
            chunk_dir = _chunk_dir(upload_id)
            os.makedirs(chunk_dir, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='part-', dir=chunk_dir) as work_dir:
                source = os.path.join(work_dir, 'part')
                part.save(source)
                upload.update(pull__finished_parts=idx)
                os.replace(source, os.path.join(chunk_dir, str(idx)))
    return 'OK'

@app.route('/api/1/multiupload/verify_part', methods={'POST'})
def verify_chunk():
    user = verify_token()
    if not user:
        abort(403)

    upload_id = _upload_id()
    with _upload_lock(upload_id):
        upload = _get_upload(upload_id)
        idx = _part_index(upload)
        if upload.done:
            return jsonify(result=True)
        chunk_path = os.path.join(_chunk_dir(upload_id), str(idx))
        try:
            with open(chunk_path, 'rb') as chunk:
                if gen_hash(chunk, 'sha256', read_size=1024 * 1024) != request.form['checksum']:
                    return jsonify(result=False, reason='checksum')
        except FileNotFoundError:
            return jsonify(result=False, reason='part missing')
        upload.update(add_to_set__finished_parts=idx)
    return jsonify(result=True)


def _part_index(upload):
    idx = request.form.get('part', type=int)
    if idx is None or not 0 <= idx < upload.total_parts:
        abort(400)
    return idx

