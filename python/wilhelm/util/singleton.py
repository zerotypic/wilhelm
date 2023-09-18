#
# singleton : Metaclass for singleton classes
#

class SingletonMeta(type):
    _singleton = None
    def __call__(cls, *args, **kwargs):
        if cls._singleton == None:
            cls._singleton = super().__call__(*args, **kwargs)
        #endif
        return cls._singleton
    #enddef
#endclass
