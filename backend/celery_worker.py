from app import create_app, celery, make_celery


app = create_app()
app.app_context().push()

make_celery(app)

## Добавляем задачи для сельдерея сюда 
# например: from app.structure import Structure
from app.ntfs.tasks import get_virustotal_verdict