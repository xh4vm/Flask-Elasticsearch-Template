from . import IHashHandler
from typing import Union
import re


class SHA256Handler(IHashHandler):

    def __init__(self, sha256 : str = None) -> None:
        self.sha256 = sha256

    def get(self) -> Union[str, Exception]:
        if self.sha256 is not None and re.match('[0-9a-z]{64}', self.sha256, flags=re.IGNORECASE) is None:
            raise ValueError("SHA256 hash error")

        return self.sha256 or ''