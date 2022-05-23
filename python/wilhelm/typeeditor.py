#
# typeditor : UI for editing types
#

import enum

import idaapi

class Exn(Exception): pass

# class AbstractDispToken(object): pass

# class LineSepDispToken(AbstractDispToken): pass

# class DispToken(AbstractDispToken):
#     def __init__(self, s, func=None, func_ctx=None):
#         self.value = s
#         self.func = func
#         self.func_ctx = func_ctx
#     #enddef
#     def to_colstr(self): return self.value
#     def act(self, vkey, shift):
#         if self.func: self.func(vkey, shift, ctx=self.func_ctx)
#     #enddef
#     def __repr__(self): return "<{} '{}'>".format(self.__class__.__name__, self.to_colstr())
# #endclass

from . import util
from .util import tokenizedviewer
from .util.tokenizedviewer import Token

class ActionCodes(enum.Enum):
    UNKNOWN = 0
    NAVIGATE = 1
    RENAME = 2
#endclass

class StructMemberView(tokenizedviewer.View):
    def __init__(self, parent, index, memb):
        self.parent = parent
        self.index = index
        self.memb = memb
        self.memb_type = self.memb.type._print()
        self.memb_name = self.memb.name
    #enddef

    def render(self):
        return [
            Token.ACT(self.memb_type, self.act_type),
            Token.ACT(self.memb_name, self.act_name),
            Token.DISP(";")
        ]
    #enddef

    def act_type(self, code):
        print("act_type called!")
    #enddef

    def act_name(self, code):
        print("act_name called!")
    #enddef

#endclass
    
class StructView(tokenizedviewer.View):

    def __init__(self, ti):
        self.ti = ti
        self.struct_name = self.ti.get_type_name()
        
        udt = idaapi.udt_type_data_t()
        self.ti.get_udt_details(udt)

        self.memb_views = [
            StructMemberView(self, i, memb)
            for (i, memb) in enumerate(udt)]
            
    #enddef

    def render(self):
        toklist = []
        toklist += [
            Token.DISP("struct"),
            Token.ACT(self.struct_name, self.act_struct_name),
            Token.DISP("{"),
            Token.SEP()
        ]

        for mv in self.memb_views:
            toklist += [Token.DISP("   ")] + mv.render() + [Token.SEP()]
        #enddef

        toklist += [Token.DISP("};"), Token.SEP()]

        return toklist
    #enddef

    def act_struct_name(self, code):
        print("act_struct_name called!")
    #enddef
    
    
#endclass


KEY_MAP = {
    (13, 0) : ActionCodes.NAVIGATE,
    (78, 0) : ActionCodes.RENAME,
}

class TypeEditor(tokenizedviewer.TokenizedViewer):

    def __init__(self):
        super().__init__(KEY_MAP)
        self.ti = None
    #enddef
    
    def Create(self):
        super().Create("Type Editor")
    #enddef

    def set_type(self, tyname):
        self.ti = idaapi.tinfo_t()
        self.ti.get_named_type(idaapi.get_idati(), tyname)
        self.set_view(StructView(self.ti))
    #enddef

#endclass
