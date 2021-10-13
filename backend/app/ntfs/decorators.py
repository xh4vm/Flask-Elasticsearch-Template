from functools import wraps
from .models import Fingerprint, Object
from flask import jsonify, request


def fingerprint_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'fingerprint_id' not in kwargs:
            abort(400)

        fingerprint = Fingerprint.query.get(kwargs['fingerprint_id'])

        if fingerprint is None:
            abort(404)

        kwargs['fingerprint'] = fingerprint
        del kwargs['fingerprint_id']

        return f(*args, **kwargs)

    return decorated_function

def object_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'object_id' not in kwargs:
            abort(400)

        _object = Object.query.get(kwargs['object_id'])

        if _object is None:
            abort(404)

        kwargs['object'] = _object
        del kwargs['object_id']

        return f(*args, **kwargs)

    return decorated_function