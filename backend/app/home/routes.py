import requests
from ..db import db
from flask import jsonify, render_template
from sqlalchemy.orm.scoping import scoped_session
from flask_classy import FlaskView, route


class Home(FlaskView):
    session: scoped_session = db.session

    def get(self):
        return render_template("home/index.html"), 200
