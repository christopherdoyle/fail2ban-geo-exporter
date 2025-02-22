from ..config import Settings


class BaseProvider:
    def __init__(self, settings: Settings):
        self.settings = settings

    def annotate(self, ip):
        return {}

    def get_labels(self):
        return []
