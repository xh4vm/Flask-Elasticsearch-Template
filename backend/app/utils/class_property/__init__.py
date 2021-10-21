from .class_property_descriptor import ClassPropertyDescriptor


def classproperty(func):
    if not isinstance(func, (classmethod, staticmethod)):
        func = classmethod(func)

    return ClassPropertyDescriptor(func)