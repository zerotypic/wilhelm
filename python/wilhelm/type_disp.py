#
# type_disp : Convert WilTypes into human-readable strings and back
#

import pyparsing as pp
import json

import idaapi

from . import types as T
from . import util

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = util.setup_logger(__name__)

class Exn(Exception): pass
class ConversionExn(Exn): pass
class UnsupportedTypeExn(Exn): pass

_PRIMITIVE_MAP = {
    "Unit": "void",
    "Int8": "int8",
    "Int16": "int16",
    "Int32": "int32",
    "Int64": "int64",
    "Int128": "int128",
    "UInt8": "uint8",
    "UInt16": "uint16",
    "UInt32": "uint32",
    "UInt64": "uint64",
    "UInt128": "uint128",
    "Bool": "bool",
    "Float": "float",
    "Double": "double",
    "LDouble": "ldouble"
}
_PRIMITIVE_MAP_REV = dict(((v, k) for (k, v) in _PRIMITIVE_MAP.items()))

SUPPORTED_TYPES = (T.Primitive, T.Pointer, T.Array, T.Function, T.NamedRef)

#
# TYPES TO DISPLAY STRINGS
#

def to_dispstr(ty):
    '''Convert type to display string.
        
    Converts a type into a string form meant for human viewing and editing.
    '''
    def conv(ty): return to_dispstr(ty).strip()
    def guard(dispstr):
        if " " in dispstr and dispstr[0] != "(":
            return "(" + dispstr + ")"
        else:
            return dispstr
        #endif
    #enddef
    def conv_and_guard(ty): return guard(conv(ty))
    
    match ty:
        
        case T.Primitive(_name = _name):
            if _name in _PRIMITIVE_MAP:
                return _PRIMITIVE_MAP[_name]
            else:
                raise ConversionExn("Unknown primitive {}".format(_name))
            #endif

        case T.Pointer(target=ty):
            tystr = conv(ty)
            if tystr[-1] == "*":
                return tystr + "*"
            else:
                return guard(tystr) + " *"
            #endif

        case T.Function(_cc = cc, args=args, ret_ty=ret_ty,
                        _storeinfo=storeinfo, _spoilinfo=spoilinfo):
            dispstr =  "{cc} ({args}) -> {ret_ty}".format(
                cc=cc.name,
                args=", ".join(("{} : {}".format(n, conv(ty)) for (n, ty) in args)),
                ret_ty=conv(ret_ty)
            )
            if storeinfo != None:
                (args_store, ret_store) = storeinfo
                dispstr += " (({}), {})".format(
                    ", ".join((
                        "{}={}({})".format(arg_name, loc_spec.name, loc_value)
                        for (arg_name, (loc_spec, loc_value))
                        in args_store.items()
                    )),
                    ret_store if ret_store else "None"
                )
            #endif
            if spoilinfo != None:
                dispstr += " ({})".format(", ".join((r for r in spoilinfo)))
            #endif
            return "{" + dispstr + "}"
       
        case T.Array(elem_ty=elem_ty, capacity=capacity):
            elemstr = conv(elem_ty)
            if elemstr[-1] != "]": elemstr = guard(elemstr)
            return "{}[{:d}]".format(conv_and_guard(elem_ty), capacity)

        case T.NamedRef(tyname=tyname):
            return tyname.fullname

        case _:
            raise UnsupportedTypeExn("Cannot convert type {!r} to dispstr.".format(ty))
            
    #endmatch
    
#enddef

#
# DISPLAY STRINGS TO TYPES
#

# XXX: A lot of this is copied from path.py, probably want to consolidate
# helper stuff into some util/ module.

#
# Helper decorator for creating parsers.
#
def parser(ppelem):
    def _decorator(func):
        ppelem.setParseAction(func)
        return ppelem
    #enddef
    return _decorator
#enddef

pp.ParserElement.enable_left_recursion()

DispString = pp.Forward()

Identifier = pp.Word(pp.alphas + "_", bodyChars=pp.alphanums + "_")
TypeName = Identifier.copy()
ArgName = Identifier.copy()

@parser((pp.Combine(pp.Literal("0x") + pp.Word(pp.hexnums))) |
        (pp.Combine(pp.Literal("0b") + pp.Word("01"))) |
        (pp.Combine(pp.Literal("0") + pp.Word("01234567"))) |
        pp.Word(pp.nums)
    )
def Num(tok):
    return int(tok[0], base=0)
#enddef

@parser(pp.Opt(pp.Literal("-")("neg")) + Num("num"))
def SignedNum(tok):
    if "neg" in tok:
        return tok.num * -1
    else:
        return tok.num
    #enddef
#enddef

@parser(pp.MatchFirst((pp.Literal(v) for v in _PRIMITIVE_MAP_REV.keys())))
def Primitive(tok):
    return T.Primitive.get_by_name(_PRIMITIVE_MAP_REV[tok[0]])
#enddef

@parser(DispString + pp.Literal("*"))
def Pointer(tok):
    return T.Pointer(tok[0])
#enddef

@parser(DispString + pp.Literal("[") + Num("capacity") + pp.Literal("]"))
def Array(tok):
    return T.Array(tok[0], tok.capacity)
#enddef

@parser(pp.MatchFirst([pp.Literal(cc.name) for cc in T.Function.CC]))
def CallingConvention(tok):
    return getattr(T.Function.CC, tok[0])
#enddef

@parser(Identifier + pp.Literal(":") + DispString)
def FunctionArg(tok):
    return (tok[0], tok[2])
#enddef

FunctionArgList = pp.Group(pp.DelimitedList(FunctionArg, ","))

@parser(pp.Literal("REG(") + Identifier("reg") + pp.Literal(")"))
def FunctionRegLoc(tok):
    return T.Function.LOC_REG(tok.reg)
#enddef

@parser(pp.Literal("STACK(") + SignedNum("stack") + pp.Literal(")"))
def FunctionStackLoc(tok):
    return T.Function.LOC_STACK(tok.stack)
#enddef

FunctionArgLoc = FunctionRegLoc | FunctionStackLoc

@parser(Identifier("arg_name") + pp.Literal("=") + FunctionArgLoc("arg_loc"))
def FunctionArgSpec(tok):
    return (tok.arg_name, tok.arg_loc[0])
#enddef

FunctionArgsStore = pp.Group(pp.DelimitedList(FunctionArgSpec, ","))

@parser(pp.Literal("(") +
        pp.Literal("(") + 
        pp.Opt(FunctionArgsStore("args_store")) +
        pp.Literal(")") +
        pp.Literal(",") +
        Identifier("ret_store") +
        pp.Literal(")"))
def FunctionStoreInfo(tok):
    return (
        dict(list(tok.args_store)) if "args_store" in tok else {},
        tok.ret_store if tok.ret_store != "None" else None)
#enddef

@parser(pp.Literal("()"))
def EmptyFunctionStoreInfo(tok):
    return ({}, "None")
#enddef

@parser(pp.Literal("(") +
        pp.Group(pp.DelimitedList(Identifier, ",")) +
        pp.Literal(")"))
def FunctionSpoilInfo(tok):
    return tok[1]
#enddef

@parser(pp.Literal("{") +
        CallingConvention("cc") +
        pp.Literal("(") + pp.Opt(FunctionArgList("args")) + pp.Literal(")") +
        pp.Literal("->") + DispString +
        pp.Opt((FunctionStoreInfo | EmptyFunctionStoreInfo)("storeinfo")) +
        pp.Opt(FunctionSpoilInfo("spoilinfo")) +
        pp.Literal("}"))
def Function(tok):
    return T.Function(
        list(tok.args),
        tok[6],                 # the DispString matching the return type
        cc=tok.cc,
        storeinfo=tok.storeinfo[0] if "storeinfo" in tok else None,
        spoilinfo=list(tok.spoilinfo) if "spoilinfo" in tok else None)
#enddef

@parser(TypeName)
def NamedRef(tok):
    try:
        return T.NamedRef(tok[0])
    except T.UnknownTypeNameExn:
        raise ConversionExn("Could not convert dispstring to type.")
    #endtry
#enddef

DispString <<= (Array | Pointer | Function | Primitive | NamedRef)

def from_dispstr(dispstr):
    return DispString.parse_string(dispstr)[0]
#enddef

#
# EXTENDED TYPES TO STRUCTURED DISPLAY TOKENS
#

from .util import disptokens
from .util.disptokens import Token, DispToken, LinkedToken

# COLOR CONSTANTS FOR TYPES
SCOLOR_DEFAULT = idaapi.SCOLOR_REG
SCOLOR_SIZE = idaapi.SCOLOR_HIDNAME
SCOLOR_OFFSET = idaapi.SCOLOR_HIDNAME
SCOLOR_TYPE = idaapi.SCOLOR_DNAME
SCOLOR_ELEM_NAME = idaapi.SCOLOR_LIBNAME
SCOLOR_COMMENT = idaapi.SCOLOR_NUMBER

class KeywordToken(DispToken): _color = SCOLOR_DEFAULT
class SymbolToken(DispToken): _color = SCOLOR_DEFAULT
class StructToken(LinkedToken): _color = SCOLOR_DEFAULT
class StructNameToken(StructToken): _color = SCOLOR_TYPE
class StructSizeToken(StructToken): _color = SCOLOR_SIZE
class StructFieldToken(StructToken): pass
class StructFieldOffsetToken(StructFieldToken): _color = SCOLOR_OFFSET
class StructFieldNameToken(StructFieldToken): _color = SCOLOR_ELEM_NAME
class StructFieldTypeToken(StructFieldToken): _color = SCOLOR_TYPE

def to_disptokens(ty_name, ty):

    def make_dispstr(ty):
        try:
            return to_dispstr(ty)
        except UnsupportedTypeExn as e:
            return "!(unsupported type)"
        #endtry
    #enddef
    
    match ty:

        case T.Struct(fields=fields, total_size=total_size):

            calced_fields = ty.get_calced_field_info()
            
            field_tokens = []
            for (i, (calced_offset, offset, name, field_ty)) in enumerate(calced_fields):
                if offset < 0:
                    offset_str = " ={:04x}:  ".format(calced_offset)
                else:
                    offset_str = "  {:04x}:  ".format(offset)
                #endif
                ty_name_str = make_dispstr(field_ty)
                field_name_str = idaapi.COLSTR(name, SCOLOR_ELEM_NAME)

                field_tokens += (
                    StructFieldOffsetToken(offset_str, (ty, i)),
                    StructFieldTypeToken(make_dispstr(field_ty), (ty, i), addspace=True),
                    StructFieldNameToken(name, (ty, i)),
                    SymbolToken(";"),
                    Token.SEP()
                )
            #endfor
            if total_size != None:
                size_str = "size=0x{:03x}".format(total_size)
            else:
                size_str = "size=auto(0x{:03x})".format(ty.bytesize)
            #endif
            size_str = idaapi.COLSTR(size_str, SCOLOR_SIZE)
            return (
                KeywordToken("struct", addspace=True),
                StructNameToken(ty_name, ty, addspace=True),
                StructSizeToken(size_str, ty, addspace=True),
                SymbolToken("{"),
                Token.SEP(),
            ) + tuple(field_tokens) + (
                SymbolToken("};"),
            )
        case _:
            raise UnsupportedTypeExn("Cannot convert type {!r} to disptokens.".format(ty))

    #endmatch
    
#enddef

# XXX: UNIT TESTS!
