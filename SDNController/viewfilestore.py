
class viewfilestore(object):

    instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.instance:
            cls.instance = super(viewfilestore, cls).__new__(cls, *args, **kwargs)
        return cls.instance

    def __init__(self):
        self.nv_path=""

    def setNVPath(self,path):
        self.nv_path = path

    def getNVPath(self):
        return self.nv_path