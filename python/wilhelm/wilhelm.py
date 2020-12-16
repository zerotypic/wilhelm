#
# wilhelm : Wrapper for Hex-Rays API
#

import idaapi

class Exn(Exception): pass

def pad_struct(ordinal, size):

    ltil = idaapi.get_idati()

    tinfo = idaapi.get_numbered_type(ltil, ordinal)

    if tinfo == None: raise Exn("Cannot load type with ordinal number %d" % ordinal)

    
    
    
        
    

    
#enddef
