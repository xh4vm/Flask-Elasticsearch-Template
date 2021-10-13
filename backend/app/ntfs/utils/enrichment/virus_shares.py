import requests
import re


class VirusShares:
    def __init__(self, host : str = "https://virusshare.com"):
        self.host = "https://virusshare.com"

    def get_link_pages(self):
        response = requests.get(self.host+"/hashes")
        return re.findall("hashfiles/VirusShare_[0-9]+.md5", response.text)

    def get_hash_from_page(self, link_page : str):
        response = requests.get(self.host+'/'+link_page)
        hashes = re.sub('#[^\n]*\n', '', response.text).split("\n")

        return hashes

    def get(self):
        link_pages = self.get_link_pages()

        hashes = []
        for link_page in link_pages:
            hashes.extend(self.get_hash_from_page(link_page))