from . import IHashHandler
from typing import Union
import re


class SHA1Handler(IHashHandler):

    def __init__(self, sha1 : str = None) -> None:
        self.sha1 = sha1

    def get(self) -> Union[str, Exception]:
        if self.sha1 is not None and re.match('[0-9a-z]{40}', self.sha1, flags=re.IGNORECASE) is None:
            raise ValueError("SHA1 hash error")

        return self.sha1