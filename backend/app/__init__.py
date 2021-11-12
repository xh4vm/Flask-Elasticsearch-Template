from celery import Celery
from config import Config
from .extensions.flask_elastic import FlaskElastic
from flask_migrate import Migrate
from flask_redis import FlaskRedis
from .db import db
from .extensions.jinja2.filters import *


migrate = Migrate()
redis_client = FlaskRedis()
celery = Celery(__name__, backend=Config.RESULT_BACKEND, broker=Config.BROKER_URL)

def register_blueprints(app):
    from app.home import bp as home_bp
    app.register_blueprint(home_bp)

    from app.file_analyser import bp as file_analyser_bp
    app.register_blueprint(file_analyser_bp)

def register_jinja2_filters(app):
    app.jinja_env.filters.update({"fromjson": fromjson})

def create_app(config_class=Config):
    app = FlaskElastic(__name__, config_class=config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    redis_client.init_app(app)
    celery.conf.update(app.config)

    register_blueprints(app)
    register_jinja2_filters(app)

    app.app_context().push()

    return app
    

def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['RESULT_BACKEND'],
        broker=app.config['BROKER_URL']
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    celery.config_from_object(__name__)
    return celery
