from flask import Blueprint

from .routes import NTFS

bp = Blueprint('ntfs', __name__, url_prefix='/ntfs')
NTFS.register(bp, route_base='/')