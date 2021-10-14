from . import IHashHandler
from typing import Union
import re


class MD5Handler(IHashHandler):

    def __init__(self, md5 : str = None) -> None:
        self.md5 = md5

    def get(self) -> Union[str, Exception]:
        if self.md5 is not None and re.match('[0-9a-z]{32}', self.md5, flags=re.IGNORECASE) is None:
            raise ValueError("MD5 hash error")

        return self.md5 or ''