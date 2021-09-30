from celery import Celery
from config import Config
from .flask_elastic import FlaskElastic
from flask_migrate import Migrate
from flask_redis import FlaskRedis


from .db import db

migrate = Migrate()
redis_client = FlaskRedis()
celery = Celery(__name__, backend=Config.CELERY_RESULT_BACKEND, broker=Config.CELERY_BROKER_URL)

def register_blueprints(app):
    from app.ntfs import bp as ntfs_bp
    app.register_blueprint(ntfs_bp)


def create_app(config_class=Config):
    app = FlaskElastic(__name__, config_class=config_class)

    db.init_app(app)
    migrate.init_app(app, db)
    redis_client.init_app(app)

    register_blueprints(app)

    app.app_context().push()

    return app
    

def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)

    class ContextTask(celery.Task):
        def __call__(self, *args, **kwargs):
            with app.app_context():
                return self.run(*args, **kwargs)

    celery.Task = ContextTask
    return celery
