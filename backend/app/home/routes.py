from ..db import db
from flask import jsonify
from sqlalchemy.orm.scoping import scoped_session
from app.home.models import User
from flask_classy import FlaskView, route


class Home(FlaskView):
    session: scoped_session = db.session

    def get(self):
        print(User.search("Kirill", ['first_name']))
        return "asd", 200

    @route('/add/', methods=['GET'])
    def add(self):
        user = User(nickname="xh4vm", first_name="Kirill", email="xoklhyip@yandex.ru")
       
        self.session.add(user)
        self.session.commit()

        return jsonify(), 200


