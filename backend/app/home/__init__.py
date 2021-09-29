from flask import Blueprint

from .routes import Home

bp = Blueprint('home', __name__, url_prefix='/home')
Home.register(bp, route_base='/')