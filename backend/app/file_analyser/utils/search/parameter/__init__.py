import re
from app.utils.class_property import classproperty


class Parameter:
    @classproperty
    def __parameter__(cls):
        return re.sub('(?!^)([A-Z][a-z]+)', r'_\1', cls.__name__).lower()