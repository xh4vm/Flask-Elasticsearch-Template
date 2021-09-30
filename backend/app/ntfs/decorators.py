from functools import wraps
from .models import ObjectFS
from flask import jsonify, request


def object_fs_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'object_fs_id' not in kwargs:
            abort(400)

        object_fs = ObjectFS.query.get(kwargs['object_fs_id'])

        if object_fs is None:
            abort(404)

        kwargs['object_fs'] = object_fs
        del kwargs['object_fs_id']

        return f(*args, **kwargs)

    return decorated_function