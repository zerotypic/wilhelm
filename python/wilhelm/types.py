#
# types : Type system
#

# XXX: Temporary type while we work on AST first.
class WilType:

    def __init__(self, tinfo):
        self._tinfo = tinfo
    #enddef

    def to_tinfo(self): return self._tinfo

    @classmethod
    def from_tinfo(cls, tinfo):
        return cls(tinfo)
    #enddef
    
#endclass


# Given an address, determine the type of object located there.
def from_addr(addr, width):
    # XXX: Implement!
    # Can use idaapi.get_tinfo() function. Note it appears that the
    # function returns false for cases where there is no type info,
    # which is probably the case for primitive types. In those cases we
    # can probably determine the type by getting the flags for that
    # address (idaapi.get_flags()) and testing the flags.
    return None
#enddef
