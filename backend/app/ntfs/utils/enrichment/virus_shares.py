import requests
import re


class VirusShares:
    __host__= "https://virusshare.com"

    def __init__(self):
        pass

    @classmethod
    def get_link_pages(cls):
        response = requests.get(cls.__host__+"/hashes")
        return re.findall("hashfiles/VirusShare_[0-9]+.md5", response.text)

    @classmethod
    def get_hash_from_page(cls, link_page : str):
        response = requests.get(cls.__host__+'/'+link_page)
        hashes = re.sub('#[^\n]*\n', '', response.text).split("\n")

        return hashes

    @classmethod
    def get(cls):
        link_pages = cls.get_link_pages()

        hashes = []
        for link_page in link_pages:
            hashes.extend(cls.get_hash_from_page(link_page))