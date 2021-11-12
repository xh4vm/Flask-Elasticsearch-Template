from flask import Blueprint

from .routes import FileAnalyser
from .discovery.routes import Discovery
from .enrichment.routes import Enrichment

bp = Blueprint('file_analyser', __name__, url_prefix='/file_analyser')
FileAnalyser.register(bp, route_base='/')
Discovery.register(bp, route_base='/')
Enrichment.register(bp, route_base='/')
