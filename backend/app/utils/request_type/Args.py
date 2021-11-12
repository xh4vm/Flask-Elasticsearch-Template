from app.utils.request_type import IRequestType
from flask import request


class Args(IRequestType):

    def get(self) -> dict:
        return request.args