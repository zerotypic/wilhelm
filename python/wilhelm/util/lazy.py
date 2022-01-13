#
# lazy : Metaclass for creating generic lazy objects
#

from .immutable import immdict

class LazyMeta(type):
    '''Metaclass for lazy instantiation.
    
    When this is used as a class's metaclass, initialization of objects of
    that class will happen lazily: `__init__` gets called only when an attempt
    is made to access an attribute of the object.

    A separate pre-initialization function for lazy objects can be used:
    `__lazy_preinit__`, which will be called right away. This allows values to
    be set on the lazy object, which when accessed will not result in
    reification. `__lazy_preinit__` is called with the same arguments as
    `__init__`, i.e. the arguments provided to the constructor.

    Note that if `__lazy_preinit__` is defined for a lazy class, then any
    subclass of that class whose `__init__` defines different arguments, must
    similarly have a `__lazy_preinit__` accepting those arguments. Otherwise,
    an exception might be thrown when the constructor arguments get passed to
    the superclass's `__lazy_preinit__`.
    '''

    def __init__(realcls, name, bases, dct):
        super().__init__(name, bases, dct)
       
        # We mint a new lazy class for each class of this metaclass.
        # XXX: Document!
        class _Lazy(object):

            def __new__(cls, args, kwargs):
                # Use the real class's __new__ to get a new object instance.
                obj = realcls.__new__(realcls, *args, **kwargs)
                # Call lazy preinit if it exists
                if hasattr(realcls, "__lazy_preinit__"):
                    realcls.__lazy_preinit__(obj, *args, **kwargs)
                #endif
                # Store info we need to reify object.
                obj.__lazy_info = (args, kwargs)
                # Replace the class with _Lazy until reified.
                obj.__class__ = cls
                return obj
            #enddef

            def __reify__(self):
                (args, kwargs) = self.__lazy_info
                del self.__dict__["_Lazy__lazy_info"]
                super().__setattr__("__class__", realcls)
                self.__init__(*args, **kwargs)
            #enddef
        
            def __getattr__(self, name):
                self.__reify__()
                return getattr(self, name)
            #enddef

            def __setattr__(self, name, value):
                self.__reify__()
                setattr(self, name, value)
            #enddef
    
            def __repr__(self):
                (args, kwargs) = self.__lazy_info
                return "Lazy{}{}".format(realcls.__qualname__, (args, kwargs))
            #enddef

        #endclass
        _Lazy.__name__ = "{}_Lazy".format(realcls.__name__)
        _Lazy.__qualname__ = "{}_Lazy".format(realcls.__qualname__)
        realcls._Lazy = _Lazy
        
    #enddef
    
    def __call__(cls, *args, **kwargs):
        # Whenever an object of type `cls` is to be created, return a lazy
        # version instead.
        return cls._Lazy(args, kwargs)
    #enddef

    # Override type checks so lazy objects appear to be of the same type as
    # the reified object.
    
    def __instancecheck__(cls, instance):
        return super().__instancecheck__(instance) or isinstance(instance, cls._Lazy)
    #enddef

    def __subclasscheck__(cls, subcls):
        return super().__subclasscheck__(subcls) or (subcls == cls._Lazy)
    #enddef

#endclass

class LazyFactoryMeta(LazyMeta):
    '''Metaclass for lazily instantiated objects with a keyed cache.

    When this is used as a class's metaclass, initialization of objects of
    that class happen lazily (see `LazyMeta`). In addition, a cache of
    previously created objects is maintained, such that if a request to create
    an object matches an object already in the cache, the cache object is
    returned.

    The cache is keyed via a special class method `_lazy_factory_get_key`,
    which is provided the arguments and keyword arguments that would be passed
    to `__init__`. If this method does not exist, then the `repr` of the first
    argument is used as the key. If no arguments are provided, then the key is
    set to `None`.

    XXX: Document _lazy_factory_get_key in more detail.
    XXX: Document _lazy_factory_purge_key
    '''
    
    def __init__(cls, name, bases, dct):
        super().__init__(name, bases, dct)
        cls.__lazy_factory_cache = {}
        def purge_key(cls, key):
            del cls.__lazy_factory_cache[key]
        #enddef
        cls._lazy_factory_purge_key = classmethod(purge_key)
        def get_cache(cls):
            return immdict(cls.__lazy_factory_cache)
        #enddef
        cls._lazy_factory_get_cache = classmethod(get_cache)
    #enddef

    def __call__(cls, *args, **kwargs):
        if hasattr(cls, "_lazy_factory_get_key"):
            key = cls._lazy_factory_get_key(*args, **kwargs)
        else:
            key = repr(args[0]) if len(args) > 0 else None
        #endif
        if key in cls.__lazy_factory_cache:
            return cls.__lazy_factory_cache[key]
        else:
            obj = super().__call__(*args, **kwargs)
            cls.__lazy_factory_cache[key] = obj
            return obj
        #endif
    #enddef
    
#endclass
