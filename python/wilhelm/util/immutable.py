#
# immutable : Immutable objects
#

import collections

class Exn(Exception): pass
class ImmutableExn(Exn): pass


class immdict(collections.Mapping):

    def __init__(self, d):
        self._backing_dict = d
    #enddef

    def __getitem__(self, k): return self._backing_dict.__getitem__(k)
    def __iter__(self): return self._backing_dict.__iter__()
    def __len__(self): return self._backing_dict.__len__()   
    
#endclass
