#
# storage : Persistent storage within an IDB
#

import collections

import idaapi

__all__ = ["Storage"]

class Exn(Exception): pass
class StorageExn(Exn): pass
class OversizedValueExn(Exn): pass

def _normalize_value(v):
    if type(v) == bytes:
        return v
    else:
        return str(v).encode("utf-8")
    #endif
#enddef    

class _IntMap(collections.abc.MutableMapping):

    def __init__(self, netnode):
        self._netnode = netnode
    #enddef

    def __getitem__(self, key):
        val = self._netnode.supval(int(key))
        if val == None: raise KeyError(val)
        return val
    #enddef

    def __setitem__(self, key, value):           
        value = _normalize_value(value)
        if len(value) > idaapi.MAXSPECSIZE:
            raise OversizedValueExn("Value to be stored is larger than MAXSPECSIZE")
        #endif
        rv = self._netnode.supset(int(key), value)
        if not rv:
            raise StorageExn("Error setting key %s to value %s" % (repr(key), repr(value)))
        #endif
    #enddef

    def __delitem__(self, key):
        rv = self._netnode.supdel(key)
        if not rv: raise KeyError(key)
    #enddef

    def __iter__(self):
        idx = self._netnode.sup1st()
        while idx != idaapi.BADNODE:
            yield idx
            idx = self._netnode.supnxt(idx)
        #endwhile
    #enddef

    def __len__(self):
        return len(list(self.__iter__()))
    #enddef

    def clear_all(self):
        self._netnode.supdel()
    #enddef
        
#endclass

class _StrMap(collections.abc.MutableMapping):

    def __init__(self, netnode):
        self._netnode = netnode
    #enddef

    def __getitem__(self, key):
        val = self._netnode.hashval(str(key))
        if val == None: raise KeyError(val)
        return val
    #enddef

    def __setitem__(self, key, value):
        value = _normalize_value(value)
        if len(value) > idaapi.MAXSPECSIZE:
            raise OversizedValueExn("Value to be stored is larger than MAXSPECSIZE")
        #endif
        rv = self._netnode.hashset(str(key), value)
        if not rv:
            raise StorageExn("Error setting key %s to value %s" % (repr(key), repr(value)))
        #endif
    #enddef

    def __delitem__(self, key):
        rv = self._netnode.hashdel(key)
        if not rv: raise KeyError(key)
    #enddef

    def __iter__(self):
        idx = self._netnode.hashfirst()
        while idx != None:
            yield idx
            idx = self._netnode.hashnext(idx)
        #endwhile
    #enddef

    def __len__(self):
        return len(list(self.__iter__()))
    #enddef

    def clear_all(self):
        self._netnode.hashdel_all()
    #enddef
        
#endclass  


class Storage(object):
    '''Persistent data storage.

    Can be used by other wilhelm modules to store persistent data. Backed by
    IDA Pro netnodes.
    '''

    PREFIX = "$ wilhelm."
    
    def __init__(self, name):
        self._name = name
        self._fullname = self.PREFIX + name
        self._netnode = idaapi.netnode(self._fullname)
        if not idaapi.exist(self._netnode):
            self._netnode.create(self._fullname)
        #enddef
        self._intmap = _IntMap(self._netnode)
        self._strmap = _StrMap(self._netnode)
    #enddef

    @property
    def name(self): return self._name
        
    @property
    def intmap(self): return self._intmap

    @property
    def strmap(self): return self._strmap
    
#endclass

# XXX: Tests
