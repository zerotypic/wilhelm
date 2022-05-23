#
# Utility functions and classes for wilhelm.
#

import logging
import random
import traceback
import idaapi

class Exn(Exception): pass
class TypecheckExn(Exn): pass

def TYPECHECK(v, ty):
    if not issubclass(type(v), ty):
        raise TypecheckExn("Value {} has type {}, which is incompatible with type {}.".format(
            repr(v),
            repr(type(v)),
            repr(ty)))
    #endif
#enddef

def CHECK_SUBTYPE(ty1, ty2):
    if not issubclass(ty1, ty2):
        raise TypecheckExn("Type {} is not a subclass of type {}.".format(
            repr(ty1),
            repr(ty2)))
    #endif
#enddef

# TODO: Make use of type annotations for type checking instead.

# XXX: Add at type_function implementation as well, maybe.

# Decorator that adds type checking on the positional arguments of methods.
def type_method(*sig):
    def decorator(func):
        def _f(self, *args, **kwargs):
            if len(args) < len(sig): raise TypeError
            for (a, s) in zip(args, sig): TYPECHECK(a, s)
            return func(self, *args, **kwargs)
        #enddef
        return _f
    #enddef
    return decorator
#enddef

def conv_fnumber_t(fnum):
    '''Converts a HexRays fnumber_t object into a Python float.'''
    TYPECHECK(fnum, idaapi.fnumber_t)
    # Currently relying on string parsing to do conversion as ieee.h
    # functions have not been ported to Python yet.
    strval = idaapi.fnumber_t._print(fnum)
    return float(strval)
#enddef

def get_all_names():
    '''Generator that returns all names found in an IDB database, 
    including dummy ones.'''
    cur = 0
    while True:
        cur = idaapi.next_addr(cur)
        if cur == idaapi.BADADDR: return
        name = idaapi.get_name(cur)
        if name != "": yield (cur, name)
    #endwhile
#enddef

def setup_logger(name):
    '''
    To be called within modules like this:
       (LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = util.setup_logger(__name__)
    '''
    log = logging.getLogger(name)
    return (log, log.critical, log.error, log.warning, log.info, log.debug)
#enddef

def log_exn(printer, exn, tabs=0):
    printer("\t"*tabs + "="*20)
    for l in "".join(traceback.format_exception(exn, exn, exn.__traceback__)).splitlines():
        printer("\t"*tabs + l)
    #endfor
    printer("\t"*tabs + "="*20)
#enddef

class UninitializedValue(object):
    '''Descriptor that raises an exception if it is accessed.

    Can be used for value which must be initialized before being
    accessed. Initialization would entail replacing an instance of this
    class with the actual value.'''
    def __init__(self, exn, *args, **kwargs):
        self._exn = exn
        self._args = args
        self._kwargs = kwargs
    #enddef

    def __get__(self, obj, owner=None):
        raise self._exn(*self._args, **self._kwargs)
    #enddef
#endclass

def random_name(length):
    '''Generates a random name suitable for use as an identifier.'''
    return "".join(
        [random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
         for _ in range(0,length)])
#enddef

def get_all_subclasses(cls):
    acc = []
    def _get_all(cls):
        acc.append(cls)
        for c in cls.__subclasses__(): _get_all(c)
    #enddef
    _get_all(cls)
    return acc[1:]
#enddef

def rename_ida_type_by_ordinal(ordinal, new_name):
    lt = idaapi.get_std_dirtree(idaapi.DIRTREE_LOCAL_TYPES)
    oldpath = lt.get_abspath(lt.find_entry(idaapi.direntry_t(ordinal)))
    lt.rename(oldpath, new_name)
#enddef

def rename_ida_type(old_name, new_name):
    ti = idaapi.tinfo_t()
    ti.get_named_type(idaapi.cvar.idati, old_name)
    ordinal = ti.get_ordinal()
    return rename_ida_type_by_ordinal(ordinal, new_name)
#enddef
