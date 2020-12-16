#
# ast : Access to Hex-Rays abstract syntax tree
#

import enum
import itertools
import struct
from types import GeneratorType, MethodType
NoneType = type(None)

import idaapi

from . import util
from .util import TYPECHECK, CHECK_SUBTYPE, type_method
from .util import lazylist
from . import types
from .types import WilType

class Exn(Exception): pass
class DecompilationExn(Exn): pass
class ConversionExn(Exn): pass
class NotAFunctionExn(Exn): pass
class AddressOutOfRangeExn(Exn): pass
class NonCallableAttributeExn(Exn): pass
class NonNodeAttributeExn(Exn): pass

# Operators
OP = enum.Enum("OP", (
    "NONE",
    "LNOT",
    "BNOT",
    "NEG",
    "PREINC",
    "POSTINC",
    "PREDEC",
    "POSTDEC",
    "SIZEOF",
    "LAND",
    "LOR",
    "BOR",
    "BAND",
    "BXOR",
    "PLUS",
    "MINUS",
    "TIMES",
    "SDIVIDE",
    "UDIVIDE",
    "SMOD",
    "UMOD",
    "LSL",
    "SLSR",
    "ULSR",
    "EQ",
    "NEQ",
    "SGE",
    "UGE",
    "SLE",
    "ULE",
    "SGT",
    "UGT",
    "SLT",
    "ULT",
    "FPLUS",
    "FMINUS",
    "FTIMES",
    "FDIVIDE",
    "FNEG",
))

class LocalVariable(object):
    '''
    A local variable within a function scope.
    '''

    name = ""
    ty = None

    # XXX: Type should contain width
    def __init__(self, name, ty, width, is_param=False):
        self.name = name
        self.ty = ty
        self.width = width
        self.is_param = is_param
    #enddef

#endclass

class Node(object):
    '''
    Base class for AST nodes. Nodes have a parent, and children, which can
    be accessed via the .parent and .children attributes. The children of
    a Node are Nodes themselves, and any attribute of a Node that does not
    begin with an underscore ("_") and is a subclass of Node is a child of
    that Node.
    All nodes have an associated HexRays ctree citem_t object, accessible
    via .hexrays_item.
    Note that this class overrides __getattribute__() to allow access to
    attributes starting with an underscore via the name without an
    underscore (e.g. _hexrays_item -> hexrays_item).
    '''

    def __init__(self, 
                 parent = None,
                 parent_func = None,
                 hexrays_item = None):
        self._parent = parent
        self._parent_func = parent_func
        self._ea = hexrays_item.ea
        self._hexrays_item = hexrays_item
    #enddef

    def __getattribute__(self, name):
        try:
            return super(Node, self).__getattribute__(name)
        except AttributeError as e:
            if name.startswith("_"): raise e
            try:
                return super(Node, self).__getattribute__("_" + name)
            except AttributeError:
                raise e
            #endtry
        #endtry
    #enddef

    @property
    def _children(self):
        return NodeList((getattr(self, x) for x in self.__dict__ 
                if not x.startswith("_") and
                issubclass(type(getattr(self, x)), Node)))
    #enddef

    def visit(self, visitor):
        visitor.visit(self)
    #enddef

    def descendants(self):
        def _descendants():
            yield self
            for child in self.children:
                for desc in child.descendants():
                    yield desc
                #endfor
            #endfor
        #enddef
        return NodeList(_descendants())
    #enddef

    # Checks to see if we are the descendant of <other>.
    def is_descendant_of(self, other):
        TYPECHECK(other, Node)
        if self == other: return True
        if self.parent == None: return False
        return self.parent.is_descendant_of(other)
    #enddef

    # Helper function mainly used by NodeList to access the value of an
    # attribute that may be callable. If it is callable, call it, with the
    # parameters if provided.
    def _access_attribute(self, attr_name, params = None):
        attr = getattr(self, attr_name)
        if callable(attr):
            if params == None: params = ()
            return attr(*params)
        elif params != None:
            raise NonCallableAttributeExn("Attribute {} is not callable but parameters provided.".format(attr_name))
        else:
            return attr
        #endif
    #enddef
    
#endclass

class NodeList(lazylist.MakeTypedLazyList(Node)):
    '''
    An immutable list of AST nodes. Can generally be treated like a normal
    Python tuple (not list, as Python lists are mutable). Implementation
    is lazy, delaying computation of the contents till required. Convert
    to a list if you need to modify the contents.
    '''

    #
    # Navigation and filter methods
    #

    def children(self, childspec=None):
        if childspec == None:
            return NodeList(
                (c
                 for n in self
                 for c in n.children)
            )
        else:
            return NodeList((getattr(n, childspec) for n in self))
        #endif
    #enddef

    def all(self):
        return NodeList(
            (d
             for n in self
             for d in n.descendants()
            )
        )
    #enddef

    def map_attr(self, attr_name, params=None):
        '''
        For each node in the list, map to another node or NodeList using
        that node's attribtue <attr_name>, and return the combined
        NodeList of all mapped nodes. <attr_name> must either be a node or
        a NodeList, or a callable that returns a node or a NodeList. If it
        is a callable, the parameters <params> are used to make the call.
        '''
        def _map_attr(attr_name, params):
            for n in self:
                attr = n._access_attribute(attr_name, params)
                if isinstance(attr, Node):
                    yield attr
                elif isinstance(attr, NodeList):
                    for r in attr: yield r
                else:
                    raise NonNodeAttributeExn("Attribute {} is not a Node or a NodeList.".format(attr_name))
                #endif
            #endfor
        #enddef
        return NodeList(_map_attr(attr_name, params))
    #enddef

    
    def apply(self, func):
        '''
        Applies function <func> to each node in the list. <func> is expected
        to return a NodeList, and all the resultant NodeLists are combined
        into a single NodeList which is returned.
        '''
        return NodeList(r for n in self for r in func(n))
    #enddef
        
    
    def filter_class(self, cls):
        return NodeList((n for n in self if isinstance(n, cls)))
    #enddef

    def filter_test(self, testfunc):
        return NodeList((n for n in self if testfunc(n)))
    #enddef
    
#endclass

#
# EXPRESSIONS
#

class Expr(Node): 

    @property
    def _width(self):
        # XXX: Width should be determined from the type of the expression instead.
        w = self.hexrays_item.type.get_size()
        w = struct.unpack("i", struct.pack("I", w))[0]
        return w
    #enddef

#endclass

class EmptyExpr(Expr): pass

class CommaExpr(Expr):
    @type_method(Expr, Expr)
    def __init__(self, e_lhs, e_rhs, **kwargs):
        super(CommaExpr, self).__init__(**kwargs)
        self.e_lhs = e_lhs
        self.e_rhs = e_rhs
    #enddef
#endclass

class AssignExpr(Expr):
    @type_method(Expr, Expr)
    def __init__(self, e_lhs, e_rhs, op=OP.NONE, **kwargs):
        super(AssignExpr, self).__init__(**kwargs)
        self.e_lhs = e_lhs
        self.e_rhs = e_rhs
        self._op = op
    #enddef
#endclass

class UnaOpExpr(Expr):
    @type_method(Expr)
    def __init__(self, expr, op=OP.NONE, **kwargs):
        super(UnaOpExpr, self).__init__(**kwargs)
        self.expr = expr
        self._op = op
    #enddef
#endclass

class BinOpExpr(Expr):
    @type_method(Expr, Expr)
    def __init__(self, e_lhs, e_rhs, op=OP.NONE, **kwargs):
        super(BinOpExpr, self).__init__(**kwargs)
        self.e_lhs = e_lhs
        self.e_rhs = e_rhs
        # XXX: Verify op?
        self._op = op
    #enddef
#endclass

class TernOpExpr(Expr):
    @type_method(Expr, Expr, Expr)
    def __init__(self, e_cond, e_then, e_else, **kwargs):
        super(TernOpExpr, self).__init__(**kwargs)
        self.e_cond = e_cond
        self.e_then = e_then
        self.e_else = e_else
    #enddef
#endclass

class CastExpr(Expr):
    @type_method(Expr, WilType)
    def __init__(self, expr, ty, **kwargs):
        super(CastExpr, self).__init__(**kwargs)
        self.expr = expr
        self._ty = ty
    #enddef
#endclass

class DerefExpr(Expr): 
    @type_method(Expr, int)
    def __init__(self, expr, access_size, **kwargs):
        super(DerefExpr, self).__init__(**kwargs)
        self.expr = expr
        self._access_size = access_size
    #enddef
#endclass

class RefExpr(Expr):
    @type_method(Expr)
    def __init__(self, expr, **kwargs):
        super(RefExpr, self).__init__(**kwargs)
        self.expr = expr
    #enddef
#endclass

class CallExpr(Expr):
    @type_method(Expr)
    def __init__(self, e_func, params, has_varargs=False, **kwargs):
        super(CallExpr, self).__init__(**kwargs)
        self.e_func = e_func
        self._params = params
        self._has_varargs = has_varargs
    #enddef

    @property
    def _children(self):
        def _gen():
            for c in super(CallExpr, self)._children: yield c
            for c in self._params: yield c
        #enddef
        return NodeList(_gen())
    #enddef

    def param(self, n):
        return self.params[n]
    #enddef

    def param_count(self): return len(self.params)

    def is_helper(self): return type(self.e_func) == HelperVarExpr
    
#endclass

class IndexExpr(Expr): 
    @type_method(Expr, Expr)
    def __init__(self, e_arr, e_idx, **kwargs):
        super(IndexExpr, self).__init__(**kwargs)
        self.e_arr = e_arr
        self.e_idx = e_idx
    #enddef
#endclass

class OffsetExpr(Expr):
    @type_method(Expr, int)
    def __init__(self, e_obj, offset, **kwargs):
        super(OffsetExpr, self).__init__(**kwargs)
        self.e_obj = e_obj
        self._offset = int(offset)
    #enddef
#endclass

class PtrOffsetExpr(Expr):
    @type_method(Expr, int, int)
    def __init__(self, e_obj, offset, access_size, **kwargs):
        super(PtrOffsetExpr, self).__init__(**kwargs)
        self.e_obj = e_obj
        self._offset = offset
        self._access_size = access_size
    #enddef
#endclass        

class LiteralExpr(Expr):
    def __init__(self, value, **kwargs):
        super(LiteralExpr, self).__init__(**kwargs)
        self._value = value
    #enddef
#endclass

class NumExpr(LiteralExpr): pass

class FPNumExpr(LiteralExpr): pass

class StrExpr(LiteralExpr): pass

class VarExpr(Expr): pass

class LocalVarExpr(VarExpr):
    @type_method(LocalVariable)
    def __init__(self, lvar, **kwargs):
        super(LocalVarExpr, self).__init__(**kwargs)
        self._lvar = lvar
    #enddef
#endclass

class GlobalVarExpr(VarExpr):
    @type_method(int)
    def __init__(self, addr, ty, **kwargs):
        super(GlobalVarExpr, self).__init__(**kwargs)
        self._addr = addr
        self._ty = ty
    #enddef
#endclass

class HelperVarExpr(VarExpr):
    @type_method(str)
    def __init__(self, helper_name, **kwargs):
        super(HelperVarExpr, self).__init__(**kwargs)
        self._helper_name = helper_name
    #enddef
#endclass

#
# STATEMENTS
#

class Stmt(Node): pass

class EmptyStmt(Stmt): pass

class BlockStmt(Stmt):
    def __init__(self, body, **kwargs):
        super(BlockStmt, self).__init__(**kwargs)
        self._body = body
    #enddef

    @property
    def _children(self):
        def _gen():
            for c in super(BlockStmt, self)._children: yield c
            for c in self._body: yield c
        #enddef
        return NodeList(_gen())
    #enddef

    def __getitem__(self, key): return self._children[key]
    def __iter__(self): return self._children.__iter__()

#endclass

class ExprStmt(Stmt):
    @type_method(Expr)
    def __init__(self, expr, **kwargs):
        super(ExprStmt, self).__init__(**kwargs)
        self.expr = expr
    #enddef
#endclass

class IfStmt(Stmt):
    @type_method(Expr, Stmt, Stmt)
    def __init__(self, expr, m_then, m_else, **kwargs):
        super(IfStmt, self).__init__(**kwargs)
        self.expr = expr
        self.m_then = m_then
        self.m_else = m_else
    #enddef
#endclass

class ForStmt(Stmt):
    @type_method(Expr, Expr, Expr, Stmt)
    def __init__(self, e_init, e_cond, e_step, m_body, **kwargs):
        super(ForStmt, self).__init__(**kwargs)
        self.e_init = e_init
        self.e_cond = e_cond
        self.e_step = e_step
        self.m_body = m_body
    #enddef
#endclass
        
class WhileStmt(Stmt):
    @type_method(Expr, Stmt)
    def __init__(self, e_cond, m_body, **kwargs):
        super(WhileStmt, self).__init__(**kwargs)
        self.e_cond = e_cond
        self.m_body = m_body
    #enddef
#endclass
    
class DoStmt(Stmt):
    @type_method(Expr, Stmt)
    def __init__(self, e_cond, m_body, **kwargs):
        super(DoStmt, self).__init__(**kwargs)
        self.e_cond = e_cond
        self.m_body = m_body
    #enddef
#endclass

class SwitchStmt(Stmt):
    # self.cases is of the form [( (a, b, ..), m), ...] where a and b are
    # the values for the case, and m is the body of the case.
    # The default case is the one where there are no associated values.
    @type_method(Expr)
    def __init__(self, expr, cases, **kwargs):
        super(SwitchStmt, self).__init__(**kwargs)
        self.expr = expr
        for (values, stmt) in cases: TYPECHECK(stmt, Stmt)
        self._cases = [(tuple(values), stmt) for (values, stmt) in cases]
    #enddef

    @property
    def _children(self):
        def _gen():
            for c in super(SwitchStmt, self)._children: yield c
            for (values, c) in self._cases: yield c
        #enddef
        return NodeList(_gen())
    #enddef
    
#endclass

class BreakStmt(Stmt): pass

class ContinueStmt(Stmt): pass

class ReturnStmt(Stmt):
    @type_method(Expr)
    def __init__(self, expr, **kwargs):
        super(ReturnStmt, self).__init__(**kwargs)
        self.expr = expr
    #enddef
#endclass

class GotoStmt(Stmt):
    @type_method(int)
    def __init__(self, label, **kwargs):
        super(GotoStmt, self).__init__(**kwargs)
        self._label = label
    #enddef

    def get_target(self):
        return self.parent_func.label_mapping[self.label]
    #enddef

#endclass

class AsmStmt(Stmt): pass


class Function(object):
    '''
    A decompiled function. Roughly corresponds to HexRays' cfunc_c
    class. Functions an be created by providing an address within the
    function to be decompiled.
    '''

    addr = None

    hx_func = None

    # Note that lvars is a superset of args; it includes both the local
    # variables as well as the arguments.
    lvars = []

    args = []

    body = None

    # Map from a label index to an expression. We use the same label
    # number as HexRays.
    label_mapping = None

    # Mapping from HexRays local variable index to a local variable object.
    # Currently the actual mapping is direct; the HexRays index is
    # the same as our index into self.lvars. However we keep this mapping
    # here in case in future we might re-order or insert/delete items from
    # self.lvars.
    _hx_lvars_mapping = None

    _ea_mapping = None

    def __init__(self, addr):
        '''
        Creates a new Function object.
        @param addr An address in the function to be decompiled.
        '''

        ida_func = idaapi.get_func(addr)

        # IDAPython has problems when we try to do ida_func == None, so
        # use the type instead.
        if type(ida_func) == NoneType: raise NotAFunctionExn()
            
        # Set address to starting address of the function that addr is in.
        self.addr = ida_func.start_ea

        self.hx_func = idaapi.decompile(addr)
        if type(self.hx_func) == NoneType: raise DecompilationExn()

        self._init_lvars()
        self.label_mapping = {}
        self._ea_mapping = {}
        
        self.body = self._from_hexrays(self.hx_func.body)
                                
    #enddef

    def _init_lvars(self):
        self.lvars = [LocalVariable(lvar.name, 
                                    WilType(lvar.tif),
                                    lvar.width,
                                    is_param=lvar.is_arg_var)
                      for lvar in self.hx_func.lvars]
    
        self.args = [v for v in self.lvars if v.is_param]

        self._hx_lvars_mapping = dict(enumerate(self.lvars))

    #enddef

    # Internal helper function to convert a HexRays item into a Wilhelm
    # AST node.
    def _from_hexrays(self, hx):

        # Shorthand
        def G(sub_hx): return self._from_hexrays(sub_hx)

        kwargs = {
            "hexrays_item": hx,
            "parent_func": self,
        }

        TYPECHECK(hx, idaapi.citem_t)
        
        # Store the result here first, we need to do some
        # post-processing on it below.
        result = None

        if hx.op == idaapi.cot_empty:
            result = EmptyExpr(**kwargs)
        elif hx.op == idaapi.cot_comma: # x, y
            result = CommaExpr(G(hx.x), G(hx.y), **kwargs)

        elif hx.op == idaapi.cot_asg: # x = y
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.NONE, **kwargs)
        elif hx.op == idaapi.cot_asgbor: # x |= y
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.BOR, **kwargs)
        elif hx.op == idaapi.cot_asgxor: # x ^= y
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.BXOR, **kwargs)
        elif hx.op == idaapi.cot_asgband: # x &= y
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.BAND, **kwargs)
        elif hx.op == idaapi.cot_asgadd: # x += y
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.PLUS, **kwargs)
        elif hx.op == idaapi.cot_asgsub: # x -= y
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.MINUS, **kwargs)
        elif hx.op == idaapi.cot_asgmul: # x *= y
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.TIMES, **kwargs)
        elif hx.op == idaapi.cot_asgsshr: # x >>= y signed
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.SLSR, **kwargs)
        elif hx.op == idaapi.cot_asgushr: # x >>= y unsigned
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.ULSR, **kwargs)
        elif hx.op == idaapi.cot_asgshl: # x <<= y
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.LSL, **kwargs)
        elif hx.op == idaapi.cot_asgsdiv: # x /= y signed
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.SDIVIDE, **kwargs)
        elif hx.op == idaapi.cot_asgudiv: # x /= y unsigned
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.UDIVIDE, **kwargs)
        elif hx.op == idaapi.cot_asgsmod: # x %= y signed
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.SMOD, **kwargs)
        elif hx.op == idaapi.cot_asgumod: # x %= y unsigned
            result = AssignExpr(G(hx.x), G(hx.y), op=OP.UMOD, **kwargs)
        elif hx.op == idaapi.cot_tern: # x ? y : z
            result = TernOpExpr(G(hx.x), G(hx.y), G(hx.z), **kwargs)
        elif hx.op == idaapi.cot_lor: # x || y
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.LOR, **kwargs)
        elif hx.op == idaapi.cot_land: # x && y
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.LAND, **kwargs)
        elif hx.op == idaapi.cot_bor: # x | y
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.BOR, **kwargs)
        elif hx.op == idaapi.cot_xor: # x ^ y
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.BXOR, **kwargs)
        elif hx.op == idaapi.cot_band: # x & y
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.BAND, **kwargs)
        elif hx.op == idaapi.cot_eq: # x == idaapi.y int or fpu (see EXFL_FPOP)
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.EQ, **kwargs)
        elif hx.op == idaapi.cot_ne: # x != y int or fpu (see EXFL_FPOP)
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.NEQ, **kwargs)
        elif hx.op == idaapi.cot_sge: # x >= y signed or fpu (see EXFL_FPOP)
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.SGE, **kwargs)
        elif hx.op == idaapi.cot_uge: # x >= y unsigned
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.UGE, **kwargs)
        elif hx.op == idaapi.cot_sle: # x <= y signed or fpu (see EXFL_FPOP)
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.ULE, **kwargs)
        elif hx.op == idaapi.cot_ule: # x <= y unsigned
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.SLE, **kwargs)
        elif hx.op == idaapi.cot_sgt: # x >  y signed or fpu (see EXFL_FPOP)
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.SGT, **kwargs)
        elif hx.op == idaapi.cot_ugt: # x >  y unsigned
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.UGT, **kwargs)
        elif hx.op == idaapi.cot_slt: # x <  y signed or fpu (see EXFL_FPOP)
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.SLT, **kwargs)
        elif hx.op == idaapi.cot_ult: # x <  y unsigned
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.ULT, **kwargs)
        elif hx.op == idaapi.cot_sshr: # x >> y signed
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.SLSR, **kwargs)
        elif hx.op == idaapi.cot_ushr: # x >> y unsigned
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.ULSR, **kwargs)
        elif hx.op == idaapi.cot_shl: # x << y
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.LSL, **kwargs)
        elif hx.op == idaapi.cot_add: # x + y
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.PLUS, **kwargs)
        elif hx.op == idaapi.cot_sub: # x - y
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.MINUS, **kwargs)
        elif hx.op == idaapi.cot_mul: # x * y
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.TIMES, **kwargs)
        elif hx.op == idaapi.cot_sdiv: # x / y signed
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.SDIVIDE, **kwargs)
        elif hx.op == idaapi.cot_udiv: # x / y unsigned
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.UDIVIDE, **kwargs)
        elif hx.op == idaapi.cot_smod: # x % y signed
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.SMOD, **kwargs)
        elif hx.op == idaapi.cot_umod: # x % y unsigned
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.UMOD, **kwargs)
        elif hx.op == idaapi.cot_fadd: # x + y fp
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.FPLUS, **kwargs)
        elif hx.op == idaapi.cot_fsub: # x - y fp
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.FMINUS, **kwargs)
        elif hx.op == idaapi.cot_fmul: # x * y fp
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.FTIMES, **kwargs)
        elif hx.op == idaapi.cot_fdiv: # x / y fp
            result = BinOpExpr(G(hx.x), G(hx.y), op=OP.FDIVIDE, **kwargs)
        elif hx.op == idaapi.cot_fneg: # -x fp
            result = UnaOpExpr(G(hx.x), op=OP.FNEG, **kwargs)
        elif hx.op == idaapi.cot_neg: # -x
            result = UnaOpExpr(G(hx.x), op=OP.NEG, **kwargs)
        elif hx.op == idaapi.cot_cast: # (type)x
            result = CastExpr(G(hx.x), WilType(hx.type), **kwargs)
        elif hx.op == idaapi.cot_lnot: # !x
            result = UnaOpExpr(G(hx.x), op=OP.LNOT, **kwargs)
        elif hx.op == idaapi.cot_bnot: # ~x
            result = UnaOpExpr(G(hx.x), op=OP.BNOT, **kwargs)
        elif hx.op == idaapi.cot_ptr: # *x, access size in 'ptrsize'
            result = DerefExpr(G(hx.x), hx.ptrsize, **kwargs)
        elif hx.op == idaapi.cot_ref: # &x
            result = RefExpr(G(hx.x), **kwargs)
        elif hx.op == idaapi.cot_postinc: # x++
            result = UnaOpExpr(G(hx.x), op=OP.POSTINC, **kwargs)
        elif hx.op == idaapi.cot_postdec: # x--
            result = UnaOpExpr(G(hx.x), op=OP.POSTDEC, **kwargs)
        elif hx.op == idaapi.cot_preinc: # ++x
            result = UnaOpExpr(G(hx.x), op=OP.PREINC, **kwargs)
        elif hx.op == idaapi.cot_predec: # --x
            result = UnaOpExpr(G(hx.x), op=OP.PREDEC, **kwargs)

        elif hx.op == idaapi.cot_call: # x(...)
            arglist = list(hx.a)
            has_varargs = len(arglist) > 0 and arglist[-1].is_vararg
            params = [G(e) for e in arglist]
            result = CallExpr(G(hx.x), params, has_varargs=has_varargs, **kwargs)

        elif hx.op == idaapi.cot_idx: # x[y]
            result = IndexExpr(G(hx.x), G(hx.y), **kwargs)

        elif hx.op == idaapi.cot_memref: # x.m
            result = OffsetExpr(G(hx.x), hx.m, **kwargs)

        elif hx.op == idaapi.cot_memptr: # x->m, access size in 'ptrsize'
            result = PtrOffsetExpr(G(hx.x), hx.m, hx.ptrsize, **kwargs)

        elif hx.op == idaapi.cot_num: # n
            # Note: The API appears to always return the value as an
            # unsigned 64-bit integer. We need to test if it's supposed to
            # be a signed integer, and if so, convert it.
            value = int(hx.n.value(hx.type))
            if hx.is_negative_const():
                value = struct.unpack("q", struct.pack("Q", value))[0]
            #endif
            result = NumExpr(value, **kwargs)

        elif hx.op == idaapi.cot_fnum: # fpc
            result = FPNumExpr(util.conv_fnumber_t(hx.fpc), **kwargs)

        elif hx.op == idaapi.cot_str: # string constant
            result = StrExpr(hx.string, **kwargs)

        elif hx.op == idaapi.cot_obj: # obj_ea
            # Note: Sometimes (or maybe most of the time, unsure), string
            # literals as represented in the pseudocode are returned as
            # cot_objs, where the address is that of the string in
            # memory. Detect such cases and convert to StrExpr.
            if idaapi.is_strlit(idaapi.get_flags(hx.obj_ea)):
                strtype = idaapi.get_str_type(hx.obj_ea)
                val = idaapi.get_strlit_contents(hx.obj_ea, -1, strtype)
                result = StrExpr(val, **kwargs)
            else:
                # XXX: Need to determine the type of the object at the
                # address.
                ty = types.from_addr(hx.obj_ea, hx.refwidth)
                result = GlobalVarExpr(hx.obj_ea, ty, **kwargs)
            #endif

        elif hx.op == idaapi.cot_var: # v
            result = LocalVarExpr(self._hx_lvars_mapping[hx.v.idx], **kwargs)

        elif hx.op == idaapi.cot_sizeof: # sizeof(x)
            result = UnaOpExpr(G(hx.x), op=OP.SIZEOF, **kwargs)

        elif hx.op == idaapi.cot_helper:
            # XXX: Hex-Rays uses the "helper" expression to insert
            # arbitrary names into the decompilation. Essentially, each
            # helper expression is a variable.
            result = HelperVarExpr(hx.helper, **kwargs)
            
        # INSTRUCTION TYPES START HERE

        elif hx.op == idaapi.cit_empty:
            result = EmptyStmt(**kwargs)

        elif hx.op == idaapi.cit_block: # block-statement: { ... }
            result = BlockStmt([G(x) for x in hx.cblock], **kwargs)

        elif hx.op == idaapi.cit_expr: # expression-statement: expr;
            result = ExprStmt(G(hx.cexpr), **kwargs)

        elif hx.op == idaapi.cit_if: # if-statement
            if type(hx.cif.ielse) == NoneType:
                ielse = EmptyStmt(**kwargs)
            else:
                ielse = G(hx.cif.ielse)
            #endif

            result = IfStmt(G(hx.cif.expr),
                            G(hx.cif.ithen),
                            ielse,
                            **kwargs)
            
        elif hx.op == idaapi.cit_for: # for-statement
            result = ForStmt(G(hx.cfor.init),
                             G(hx.cfor.expr),
                             G(hx.cfor.step),
                             G(hx.cfor.body),
                             **kwargs)

        elif hx.op == idaapi.cit_while: # while-statement
            result = WhileStmt(G(hx.cwhile.expr), G(hx.cwhile.body), **kwargs)

        elif hx.op == idaapi.cit_do: # do-statement
            result = DoStmt(G(hx.cdo.expr), G(hx.cdo.body), **kwargs)

        elif hx.op == idaapi.cit_switch: # switch-statement
            cases = [([v for v in case.values], G(case))
                     for case in
                     hx.cswitch.cases]
            result = SwitchStmt(G(hx.cswitch.expr), cases, **kwargs)           

        elif hx.op == idaapi.cit_break: # break-statement
            result = BreakStmt(**kwargs)

        elif hx.op == idaapi.cit_continue: # continue-statement
            result = ContinueStmt(**kwargs)

        elif hx.op == idaapi.cit_return: # return-statement
            result = ReturnStmt(G(hx.creturn.expr), **kwargs)

        elif hx.op == idaapi.cit_goto: # goto-statement
            result = GotoStmt(hx.cgoto.label_num, **kwargs)
            
        elif hx.op == idaapi.cit_asm: # asm-statement
            result = AsmStmt(**kwargs)

        else: # cot_helper, cot_insn, cot_last, cit_end
            raise ConversionExn()
        #endif

        # Add label mapping if needed.
        if not hx.label_num == -1:
            self.label_mapping[hx.label_num] = result
        #endif

        # Set the node as parent of its children.
        for c in result.children: c._parent = result

        # Add to address map.
        # We try to make sure the following:
        # - For each address, we only map to a single node
        # - We favour the node that is the least upper bound for an
        #   address
        if result.ea != idaapi.BADADDR:
            if not result.ea in self._ea_mapping:
                #print("Add to map at 0x{:08x}: {}".format(result.ea, result))
                self._ea_mapping[result.ea] = [result]
            else:
                mapping = self._ea_mapping[result.ea]
                
                # print("Mapping already exists for 0x{:08x}:".format(result.ea))
                # print("\t{}".format(repr(mapping)))

                if all((n.is_descendant_of(result) for n in mapping)):
                    # We're the ancestor node of everything in the map.

                    # Only replace the mapping with ourselves if there are
                    # more than one descendants.
                    if len(mapping) > 1:
                        # print("\tMultiple descendants, replacing.")
                        mapping.clear()
                        mapping.append(result)
                    else:
                        # Don't replace more specific descendant.
                        # print("\tSingle descendant, not replacing.")
                        pass
                    #endif
                else:
                    # We're not an ancestor, append to map.
                    # print("\tAppending to map.")
                    mapping.append(result)
                #endif
                # print("\tMap is now: {}".format(repr(mapping)))
            #endif
        #endif
        
        return result

    #enddef

    def find_by_addr(self, ea):

        while True:
            cur_func = idaapi.get_func(ea)

            # IDAPython has problems when we try to do ida_func == None, so
            # use the type instead.
            if type(cur_func) == NoneType or self.addr != cur_func.start_ea:
                raise AddressOutOfRangeExn()
            #endif

            if ea in self._ea_mapping: return self._ea_mapping[ea]
            ea = idaapi.get_item_end(ea)
        #endwhile

    #enddef

#endclass

class Visitor(object):

    def __init__(self):
        pass
    #enddef

    def visit(self, node):
        '''
        Visits the AST node <node>. Attempts to look for a visitor
        method that handles the node, based on the node's type. If there
        is no visitor method for that type, it recursively attempts fo
        find a visitor method for the supertype (i.e. superclass)
        instead. This continues until the visitor method for Node is hit,
        which is defined in the base Visitor class, thus making it the
        default visitor method.
        '''

        def visit_ty(ty):
            
            CHECK_SUBTYPE(ty, Node)

            visit_fn = getattr(self, "visit_%s" % (ty.__name__), None)
            if visit_fn == None:
                # Try the base class. There is always a base class since
                # this is a subclass of Node, and by convention every node
                # has only one parent class, or at least only one that we
                # care about.
                return visit_ty(ty.__bases__[0])
            else:
                return visit_fn(node)
            #endif
        #enddef

        return visit_ty(type(node))

    #enddef

    def visit_Node(self, node):
        return [self.visit(n) for n in node.children]
    #enddef

#endclass


# Reverse mapping to convert a HexRays op enum to a string. Useful for
# debugging.
_hxop_map = {
  idaapi.cot_empty: "cot_empty",
  idaapi.cot_comma: "cot_comma",
  idaapi.cot_asg: "cot_asg",
  idaapi.cot_asgbor: "cot_asgbor",
  idaapi.cot_asgxor: "cot_asgxor",
  idaapi.cot_asgband: "cot_asgband",
  idaapi.cot_asgadd: "cot_asgadd",
  idaapi.cot_asgsub: "cot_asgsub",
  idaapi.cot_asgmul: "cot_asgmul",
  idaapi.cot_asgsshr: "cot_asgsshr",
  idaapi.cot_asgushr: "cot_asgushr",
  idaapi.cot_asgshl: "cot_asgshl",
  idaapi.cot_asgsdiv: "cot_asgsdiv",
  idaapi.cot_asgudiv: "cot_asgudiv",
  idaapi.cot_asgsmod: "cot_asgsmod",
  idaapi.cot_asgumod: "cot_asgumod",
  idaapi.cot_tern: "cot_tern",
  idaapi.cot_lor: "cot_lor",
  idaapi.cot_land: "cot_land",
  idaapi.cot_bor: "cot_bor",
  idaapi.cot_xor: "cot_xor",
  idaapi.cot_band: "cot_band",
  idaapi.cot_eq: "cot_eq",
  idaapi.cot_ne: "cot_ne",
  idaapi.cot_sge: "cot_sge",
  idaapi.cot_uge: "cot_uge",
  idaapi.cot_sle: "cot_sle",
  idaapi.cot_ule: "cot_ule",
  idaapi.cot_sgt: "cot_sgt",
  idaapi.cot_ugt: "cot_ugt",
  idaapi.cot_slt: "cot_slt",
  idaapi.cot_ult: "cot_ult",
  idaapi.cot_sshr: "cot_sshr",
  idaapi.cot_ushr: "cot_ushr",
  idaapi.cot_shl: "cot_shl",
  idaapi.cot_add: "cot_add",
  idaapi.cot_sub: "cot_sub",
  idaapi.cot_mul: "cot_mul",
  idaapi.cot_sdiv: "cot_sdiv",
  idaapi.cot_udiv: "cot_udiv",
  idaapi.cot_smod: "cot_smod",
  idaapi.cot_umod: "cot_umod",
  idaapi.cot_fadd: "cot_fadd",
  idaapi.cot_fsub: "cot_fsub",
  idaapi.cot_fmul: "cot_fmul",
  idaapi.cot_fdiv: "cot_fdiv",
  idaapi.cot_fneg: "cot_fneg",
  idaapi.cot_neg: "cot_neg",
  idaapi.cot_cast: "cot_cast",
  idaapi.cot_lnot: "cot_lnot",
  idaapi.cot_bnot: "cot_bnot",
  idaapi.cot_ptr: "cot_ptr",
  idaapi.cot_ref: "cot_ref",
  idaapi.cot_postinc: "cot_postinc",
  idaapi.cot_postdec: "cot_postdec",
  idaapi.cot_preinc: "cot_preinc",
  idaapi.cot_predec: "cot_predec",
  idaapi.cot_call: "cot_call",
  idaapi.cot_idx: "cot_idx",
  idaapi.cot_memref: "cot_memref",
  idaapi.cot_memptr: "cot_memptr",
  idaapi.cot_num: "cot_num",
  idaapi.cot_fnum: "cot_fnum",
  idaapi.cot_str: "cot_str",
  idaapi.cot_obj: "cot_obj",
  idaapi.cot_var: "cot_var",
  idaapi.cot_insn: "cot_insn",
  idaapi.cot_sizeof: "cot_sizeof",
  idaapi.cot_helper: "cot_helper",
  idaapi.cit_empty: "cit_empty",
  idaapi.cit_block: "cit_block",
  idaapi.cit_expr: "cit_expr",
  idaapi.cit_if: "cit_if",
  idaapi.cit_for: "cit_for",
  idaapi.cit_while: "cit_while",
  idaapi.cit_do: "cit_do",
  idaapi.cit_switch: "cit_switch",
  idaapi.cit_break: "cit_break",
  idaapi.cit_continue: "cit_continue",
  idaapi.cit_return: "cit_return",
  idaapi.cit_goto: "cit_goto",
  idaapi.cit_asm: "cit_asm",
}

###############################################
# UTILITY FUNCTIONS
###############################################

def from_addr(ea = None):
    
    ea = ea if ea != None else idaapi.get_screen_ea()

    func = Function(ea)

    return func.find_by_addr(ea)

#enddef

#
# UNIT TESTS
#

import unittest

class Test(unittest.TestCase):

    def setUp(self):
        self.func_addr = idaapi.get_name_ea(idaapi.BADADDR, "test_ast")
        if self.func_addr == idaapi.BADADDR:
            raise tester.TestSetupExn("Could not find 'test_ast' function.")
        #endif
        self.func = Function(self.func_addr)
    #enddef

    def assertLocalVarExpr(self, node, name, width):
        # XXX: Check local variable type too.
        self.assertIsInstance(node, LocalVarExpr)
        self.assertIsInstance(node.lvar, LocalVariable)
        self.assertEqual(node.lvar.name, name)
        self.assertEqual(node.lvar.width, width)
    #enddef        

    def test_basic(self):

        f = self.func

        # Checks for ExprStmt, AssignExpr
        m = f.body[1]           # stru.x = 82;
        self.assertIsInstance(m, ExprStmt)
        self.assertIsInstance(m.expr, AssignExpr)

        # Checks for OffsetExpr, LocalVarExpr
        self.assertIsInstance(m.expr.e_lhs, OffsetExpr)
        self.assertIs(m.expr.e_lhs.offset, 4)
        self.assertLocalVarExpr(m.expr.e_lhs.e_obj, "stru", 16)

        # Checks for NumExpr
        self.assertIsInstance(m.expr.e_rhs, NumExpr)
        self.assertEqual(m.expr.e_rhs.value, 82)

        # Checks for PtrOffsetExpr
        e = f.body[2].expr      # stru.x = structarg->y;
        self.assertIsInstance(e.e_rhs, PtrOffsetExpr)
        self.assertEqual(e.e_rhs.offset, 4)
        self.assertLocalVarExpr(e.e_rhs.e_obj, "structarg", 4)
        self.assertEqual(e.e_rhs.access_size, 4)

        # Checks for DerefExpr
        e = f.body[3].expr      # *stru.str = dong;
        self.assertIsInstance(e.e_lhs, DerefExpr)
        self.assertIsInstance(e.e_lhs.expr, OffsetExpr)
        self.assertEqual(e.e_lhs.access_size, 1)

        # Checks for IndexExpr
        e = f.body[4].expr      # stru.str[3] = 0;
        self.assertIsInstance(e.e_lhs, IndexExpr)
        self.assertIsInstance(e.e_lhs.e_arr, OffsetExpr)
        self.assertIsInstance(e.e_lhs.e_idx, NumExpr)
        self.assertEqual(e.e_lhs.e_idx.value, 3)

        # Checks for CallExpr, GlobalVarExpr
        e = f.body[5].expr      # take_a_struct(&stru);
        self.assertIsInstance(e, CallExpr)
        self.assertIsInstance(e.e_func, GlobalVarExpr)
        addr = idaapi.get_name_ea(idaapi.BADADDR, "take_a_struct")
        self.assertEqual(e.e_func.addr, addr)
        # XXX: Check type of global variable.

        # Checks for CallExpr params, RefExpr
        self.assertEqual(len(e.params), 1)
        self.assertIsInstance(e.params[0], RefExpr)
        self.assertLocalVarExpr(e.params[0].expr, "stru", 16)

        # Checks for BinOpExpr
        e = f.body[6].expr.e_rhs # (long double)foo * 2.5;
        self.assertIsInstance(e, BinOpExpr)
        self.assertEqual(e.op, OP.FTIMES)

        # Checks for CastExpr
        self.assertIsInstance(e.e_lhs, CastExpr)
        self.assertLocalVarExpr(e.e_lhs.expr, "foo", 4)
        # XXX: Check CastExpr.ty

        # Checks for FPNumExpr
        self.assertIsInstance(e.e_rhs, FPNumExpr)
        self.assertAlmostEqual(e.e_rhs.value, 2.5)

        # Checks for ForStmt, UnaOpExpr
        m = f.body[8]           # for ( i = 0; foo > 0; ++i )
        self.assertIsInstance(m, ForStmt)
        self.assertIsInstance(m.e_init, AssignExpr)
        self.assertLocalVarExpr(m.e_init.e_lhs, "i", 4)
        self.assertIsInstance(m.e_init.e_rhs, NumExpr)
        self.assertIsInstance(m.e_cond, BinOpExpr)
        self.assertLocalVarExpr(m.e_cond.e_lhs, "foo", 4)
        self.assertIsInstance(m.e_cond.e_rhs, NumExpr)
        self.assertIsInstance(m.e_step, UnaOpExpr)
        self.assertLocalVarExpr(m.e_step.expr, "i", 4)
        self.assertEqual(m.e_step.op, OP.PREINC)

        # Checks for BlockStmt
        self.assertIsInstance(m.m_body, BlockStmt)
        self.assertEqual(len(m.m_body.body), 6)

        # Checks for TernOpExpr
        e = f.body[8].m_body.body[0].expr.e_rhs # blah <= 10 ? 52 : baz;
        self.assertIsInstance(e.e_cond, BinOpExpr)
        self.assertEqual(e.e_cond.op, OP.ULE)
        self.assertIsInstance(e.e_then, NumExpr)
        self.assertEqual(e.e_then.value, 52)
        self.assertLocalVarExpr(e.e_else, "baz", 4)

        # Checks for IfStmt, BreakStmt, EmptyStmt
        m = f.body[8].m_body.body[2] # if ( a_function(boing, foo) )
        self.assertIsInstance(m, IfStmt)
        self.assertIsInstance(m.expr, CallExpr)
        self.assertIsInstance(m.m_then, BlockStmt)
        self.assertEqual(len(m.m_then.body), 2)
        self.assertIsInstance(m.m_then.body[1], BreakStmt)
        self.assertIsInstance(m.m_else, EmptyStmt)

        # Checks for ContinueStmt
        m = f.body[8].m_body.body[4].m_else[1].m_then[0] # continue;
        self.assertIsInstance(m, ContinueStmt)

        # Checks for StrExpr
        e = f.body[8].m_body.body[5].expr.params[0]
        self.assertIsInstance(e, StrExpr)
        self.assertEqual(e.value, b"boing.")
                
        # Checks for WhileStmt
        m = f.body[9]           # while ( a_function(boing, foo) != 3 )
        self.assertIsInstance(m, WhileStmt)
        self.assertIsInstance(m.e_cond, BinOpExpr)
        self.assertIsInstance(m.m_body, BlockStmt)

        # Checks for GotoStmt
        e = f.body[9].m_body.body[1].m_then[0] # goto test;
        self.assertIsInstance(e, GotoStmt)
        self.assertEqual(e.label, 2)
        self.assertLocalVarExpr(e.get_target().expr.e_lhs, "whee", 4)

        # Checks for DoStmt
        m = f.body[10]          # do
        self.assertIsInstance(m, DoStmt)
        self.assertIsInstance(m.e_cond, BinOpExpr)
        self.assertIsInstance(m.m_body, BlockStmt)

        # Checks for SwitchStmt
        m = f.body[11]          # switch ( bar )
        self.assertIsInstance(m, SwitchStmt)
        self.assertLocalVarExpr(m.expr, "bar", 4)
        self.assertEqual(len(m.cases), 8)

        for (i, (vals, m2)) in enumerate(m.cases[:-1]):
            self.assertEqual(vals, (i,))
            self.assertIsInstance(m2, BlockStmt)
        #endfor

        self.assertEqual(m.cases[7][0], ())
        self.assertIsInstance(m.cases[7][1], BlockStmt)

        # Checks for ReturnStmt
        m = f.body[12]          # return foo + bar;
        self.assertIsInstance(m, ReturnStmt)
        self.assertIsInstance(m.expr, BinOpExpr)       

        # TODO: Missing tests for AsmStmt, EmptyExpr, CommaExpr, HelperVarExpr
        
    #enddef

    def test_tree(self):

        # Test that all children point to their parent node.
        def test_parent_link(node):
            for c in node.children:
                self.assertEqual(c.parent, node)
                test_parent_link(c)
            #endfor
        #enddef
        test_parent_link(self.func.body)

        # Test children.
        for_stmt = self.func.body[8]
        self.assertCountEqual(
            list(for_stmt.children),
            [for_stmt.e_init, for_stmt.e_cond, for_stmt.e_step, for_stmt.m_body])

        # XXX: .children checks for all other node types?

        # Test descendants.
        while_stmt = self.func.body[9]
        self.assertCountEqual(
            list(while_stmt.descendants()),
            [
                while_stmt,
                while_stmt.e_cond,
                while_stmt.e_cond.e_lhs,
                while_stmt.e_cond.e_lhs.e_func,
                while_stmt.e_cond.e_lhs.params[0],
                while_stmt.e_cond.e_lhs.params[1],
                while_stmt.e_cond.e_rhs,
                while_stmt.m_body,
                while_stmt.m_body[0],
                while_stmt.m_body[0].expr,
                while_stmt.m_body[0].expr.expr,
                while_stmt.m_body[1],
                while_stmt.m_body[1].expr,
                while_stmt.m_body[1].expr.e_lhs,
                while_stmt.m_body[1].expr.e_lhs.e_func,
                while_stmt.m_body[1].expr.e_lhs.params[0],
                while_stmt.m_body[1].expr.e_lhs.params[1],
                while_stmt.m_body[1].expr.e_rhs,
                while_stmt.m_body[1].m_then,
                while_stmt.m_body[1].m_then[0],
                while_stmt.m_body[1].m_else
            ]
        )

        self.assertTrue(
            while_stmt.m_body[1].expr.e_lhs.e_func.is_descendant_of(while_stmt)
        )

        self.assertFalse(
            while_stmt.m_body[1].expr.is_descendant_of(for_stmt)
        )
        
    #enddef

    def test_find(self):

        # XXX: Position of the break might change during compilation.
        #break_addr = idaapi.get_name_ea(idaapi.BADADDR, "test_ast") + 0xbb
        break_addr = idaapi.get_name_ea(idaapi.BADADDR, "test_ast") + 0xdf

        self.assertEqual(
            self.func.find_by_addr(break_addr)[0],
            self.func.body[8].m_body[2].m_then[1]
        )

        # Note: from_addr creates a new Function object, so the BreakStmt
        # object it returns is different from to the one in self.func.
        self.assertIsInstance(from_addr(break_addr)[0], BreakStmt)
        
    #enddef

    def test_visitor(self):

        class TestVisitor(Visitor):
            lvs = set()
            def visit_LocalVarExpr(self, e):
                self.lvs.add(e.lvar.name)
            #enddef
        #endclass

        visitor = TestVisitor()
        self.func.body.visit(visitor)
        self.assertCountEqual(
            visitor.lvs,
            ["v14", "stru", "structarg", "dong", "whee", "i", "foo",
             "blah", "baz", "v5", "boing", "v4", "bar"]
        )
        
    #enddef

    def test_nodelist(self):

        # Test children()
        
        assign_stmt = self.func.body[1]
        do_stmt = self.func.body[10]
        
        nl = NodeList([assign_stmt, do_stmt])
        
        self.assertCountEqual(
            nl.children(),
            [
                assign_stmt.expr,
                do_stmt.e_cond,
                do_stmt.m_body
            ]
        )

        # Test children() with child_sepc
        
        for_stmt = self.func.body[8]
        if_stmt1 = for_stmt.m_body[1]
        if_stmt2 = for_stmt.m_body[2]
        if_stmt3 = for_stmt.m_body[4]
        nl = NodeList([if_stmt1, if_stmt2, if_stmt3])
        self.assertCountEqual(
            nl.children(childspec="expr"),
            [if_stmt1.expr, if_stmt2.expr, if_stmt3.expr]
        )

        # Test all()
        nl = NodeList([assign_stmt, do_stmt])
        self.assertCountEqual(
            nl.all(),
            list(assign_stmt.descendants()) +
            list(do_stmt.descendants())
        )

        # Test filter_class
        
        nl = NodeList([self.func.body])

        if_stmt4 = if_stmt3.m_else[1]
        if_stmt5 = self.func.body[9].m_body[1]
        
        self.assertCountEqual(
            nl.all().filter_class(IfStmt),
            [if_stmt1, if_stmt2, if_stmt3, if_stmt4, if_stmt5]
        )
        
        # Test filter_test

        func_addr = idaapi.get_name_ea(idaapi.BADADDR, "a_function")
        def tester(node):
            return isinstance(node.e_func, GlobalVarExpr) and \
                node.e_func.addr == func_addr
        #enddef

        self.assertEqual(
            len(nl.all().filter_class(CallExpr).filter_test(tester)),
            5
        )

        # XXX: Unit tests for NodeList.apply
       
    #enddef
   
    
#endclass
