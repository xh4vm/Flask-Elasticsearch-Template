from ..models import Hash


def serialize_hash(hash : Hash):
    return {
        "id": int(hash.id),
        "md5": hash.md5,
        "sha1": hash.sha1,
        "sha256": hash.sha256
    }