#
# Utility functions and classes for wilhelm.
#

import logging
import idaapi

class Exn(Exception): pass
class TypecheckExn(Exn): pass

def TYPECHECK(v, ty):
    if not issubclass(type(v), ty):
        raise TypecheckExn("Value {} has type {}, and not of type {}.".format(
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
