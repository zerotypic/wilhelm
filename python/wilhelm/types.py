#
# types : Type system
#

import sys
import asyncio
import enum
import json
import zlib
import idaapi
from idaapi import tinfo_t

from . import event
from . import qname
from . import module
from . import storage
from . import util
from .util import TYPECHECK, TypecheckExn, UninitializedValue
from .util import asyncutils
from .util import lazy

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = util.setup_logger(__name__)

class Exn(Exception): pass
class UninitializedExn(Exn): pass
class UnimplementedExn(Exn): pass
class NoSizeExn(Exn): pass
class TInfoConversionExn(Exn): pass
class SerializeExn(Exn): pass
class UnserializeExn(Exn): pass

class FunctionExn(Exn): pass
class InvalidCallingConventionExn(FunctionExn): pass
class InvalidSpoilInfoExn(FunctionExn): pass
class InvalidStoreInfoExn(FunctionExn): pass

class NamedRefExn(Exn): pass
class UnknownTypeNameExn(NamedRefExn): pass

class UDTExn(Exn): pass
class InvalidUDTSpecExn(UDTExn): pass
class InvalidUDTSizeExn(UDTExn): pass

class StructExn(Exn): pass
class InvalidFieldsExn(StructExn): pass
class InvalidFieldNameExn(StructExn): pass
class InvalidFieldSpecExn(StructExn): pass
class InvalidSizeExn(StructExn): pass
class InvalidOffsetExn(StructExn): pass
class CannotPreserveSizeExn(StructExn): pass

class PolyTInfoExn(Exn): pass
class PolyTypeSizeExn(Exn): pass

class ContextExn(Exn): pass
class DuplicateNameExn(ContextExn): pass

class Sizes:
    ADDR = UninitializedValue(UninitializedExn)
#endclass

_PRIMITIVE_MAP = {
    #             Size  Signed C Name    IDA Basic Type       IDA is-type Function
    "Unit"    : ( None, False, "void",     idaapi.BTF_VOID,   tinfo_t.is_void),

    "Int8"    : (  1, True,  "__int8",   idaapi.BTF_INT8,   tinfo_t.is_char),
    "Int16"   : (  2, True,  "__int16",  idaapi.BTF_INT16,  tinfo_t.is_int16),
    "Int32"   : (  4, True,  "__int32",  idaapi.BTF_INT32,  tinfo_t.is_int32),
    "Int64"   : (  8, True,  "__int64",  idaapi.BTF_INT64,  tinfo_t.is_int64),
    "Int128"  : ( 16, True,  "__int128", idaapi.BTF_INT128, tinfo_t.is_int128),

    "UInt8"   : (  1, False, "unsigned __int8",   idaapi.BTF_UINT8,   tinfo_t.is_uchar),
    "UInt16"  : (  2, False, "unsigned __int16",  idaapi.BTF_UINT16,  tinfo_t.is_uint16),
    "UInt32"  : (  4, False, "unsigned __int32",  idaapi.BTF_UINT32,  tinfo_t.is_uint32),
    "UInt64"  : (  8, False, "unsigned __int64",  idaapi.BTF_UINT64,  tinfo_t.is_uint64),
    "UInt128" : ( 16, False, "unsigned __int128", idaapi.BTF_UINT128, tinfo_t.is_uint128),

    "Bool"    : (  1, False, "bool", idaapi.BT_BOOL | idaapi.BTMT_BOOL1, tinfo_t.is_bool),

    "Float"   : (  4, True, "float",       idaapi.BTF_FLOAT,   tinfo_t.is_float),
    "Double"  : (  8, True, "double",      idaapi.BTF_DOUBLE,  tinfo_t.is_double),
    "LDouble" : ( 16, True, "long double", idaapi.BTF_LDOUBLE, tinfo_t.is_ldouble),
}

_SERIALIZE_ZDICT = ("".join(_PRIMITIVE_MAP.keys()) + '{"t"p":"}}}}').encode("utf-8")

class TypeEvent(event.Event):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    #enddef
#endclass

class RefChangedEvent(TypeEvent):
    '''Triggered when the underlying type of a type reference changes.'''
    def __init__(self, tyname, newty, **kwargs):
        super().__init__(tag="types", **kwargs)
        self.tyname = tyname
        self.newty = newty
    #enddef
#endclass

# Bearings for types
BRG_COMPOSITE = event.Bearing("types.composite")
BRG_COMPONENT = event.Bearing("types.component")
BRG_SUPERTYPE = event.Bearing("types.supertype")
BRG_SUBTYPE = event.Bearing("types.subtype")

@event.Relay.register(BRG_COMPOSITE, BRG_COMPONENT, BRG_SUBTYPE, BRG_SUPERTYPE)
class WilType(event.Relay):
    '''Abstract base class of all types.'''

    # Note: MUST be called after whatever setup necessary for
    # self.components() to return component types is completed.
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        # Set of types that are composed of this type, i.e. this type is a
        # component of the types in the set.
        self._composite_set = set()

        # Set of types that are subtypes of this type.
        self._subtype_set = set()

        # Register as a composite for all component types.
        for ty in self.components: ty._register_composite(self)
        
    #enddef

    def __del__(self):
        for ty in self.components: ty._unregister_composite(self)
    #enddef
    
    @property
    def is_mono(self):
        if hasattr(self, "_is_mono"): return self._is_mono
        # Determine if this is a monomorphic type.
        self._is_mono = True
        # XXX: Disabled for now.
        # for ty in self.beta_reduce()._get_all_components():
        #     if isinstance(ty, TypeVar):
        #         self._is_mono = False
        #         break
        #     #endif
        # #endfor
        return self._is_mono
    #enddef

    def assert_mono(self):
        if not self.is_mono: raise NotMonoExn("Type is not monomorphic.")
    #enddef

    def beta_reduce(self):
        # XXX: Implement!
        return self
    #enddef

    # Ensure any NamedRef children have had their forward reference resolved.
    def ensure_resolve_forward_refs(self):
        if isinstance(self, NamedRef):
            self.resolve_forward_ref()
        #endif
        for ty in self.components: ty.ensure_resolve_forward_refs()
    #enddef
    
    @property
    def bytesize(self): raise UnimplementedExn()

    def to_tinfo(self, **kwargs): raise UnimplementedExn()

    # Composite types should override this to return the components.
    @BRG_COMPONENT.adjacents_property
    def components(self): return ()

    @property
    def is_composite(self): return len(self.components) > 0
    
    def _get_all_components(self, acc=[]):
        for ty in self.components:
            ty._get_all_components(acc)
            acc.append(ty)
        #endfor
        return acc
    #enddef

    # Set of types that are composed of this type
    @BRG_COMPOSITE.adjacents_property
    def composed_in(self): return self._composite_set

    def _register_composite(self, comp):
        self._composite_set.add(comp)
    #enddef

    def _unregister_composite(self, comp):
        self._composite_set.remove(comp)
    #enddef

    # Supertypes and subtypes
    
    @BRG_SUPERTYPE.adjacents_property
    def supertypes(self): return None
    
    @BRG_SUBTYPE.adjacents_property
    def subtypes(self): return self._subtype_set
    
    def _register_subtype(self, subty):
        self._subtype_set.add(subty)
    #enddef

    def _unregister_subtype(self, subty):
        self._subtype_set.remove(subty)
    #enddef

    #
    # Serialization
    #

    def _build_properties_json(self):
        '''This is a special method that gets called to build the properties JSON
        object for serialization. Note that subclass implementations do not
        actually override the superclass's implementation, as
        WilType._to_properties_json() will actually call the implementation of
        every class in the object's class hierarchy to construct the
        properties object.

        '''
        return {}
    #enddef

    
    def _to_properties_json(self):
        '''Get properties JSON object for this type.

        This method goes through all superclasses of the object's type
        (including its actual type), calling `_build_properties_json`, and
        using the returned dict to build the properties JSON
        object. Superclasses are traversed from eldest first, so subclasses
        can possibly override properties set by a parent class.
        '''
        
        # Build list of superclasses whose _build_properties_json we need to
        # call.
        superclasses = [self.__class__]
        i = 0
        while i < len(superclasses):
            # print("i = {}".format(i))
            # print("superclasses = {!r}".format(superclasses))
            for b in superclasses[i].__bases__:
                # print("\tbase b = {!r}".format(b))
                if issubclass(b, WilType):
                    superclasses.append(b)
                #endif
            #endfor
            i += 1
        #endwhile

        #print("\tsuperclasses = {!r}".format(superclasses))
        
        # Go through the classes in reverse order, from eldest first.
        props = {}
        for c in reversed(superclasses):
            # print("\tCalling build on type {!r}".format(c))
            # print("\tbuild result: {}".format(c._build_properties_json(self)))
            props.update(c._build_properties_json(self))
            # print("\tprops is now {!r}".format(props))
        #endfor

        return props
    
    #enddef

    @classmethod
    def _from_properties_json(cls, props):
        raise UnimplementedExn()
    #enddef

    def _to_json(self):
        return {
            "t" : self.__class__.__name__,
            "p" : self._to_properties_json()
        }
    #enddef

    @classmethod
    def _from_json(cls, obj):
        tystr = str(obj["t"])
        props = obj["p"]

        for subcls in util.get_all_subclasses(cls):
            if subcls.__name__ == tystr:
                return subcls._from_properties_json(props)
            #endif
        #endfor

        raise UnserializeExn("Unknown WilType {}".format(tystr))       
        
    #enddef
    
    def serialize(self):
        jsonbytes = json.dumps(self._to_json(), separators=(",", ":")).encode("utf-8")
        comp = zlib.compressobj(level=9, wbits=-15, memLevel=9, zdict=_SERIALIZE_ZDICT)
        comp.compress(jsonbytes)
        return comp.flush()
    #enddef
   
    @classmethod
    def unserialize(cls, b):
        decomp = zlib.decompressobj(wbits=-15, zdict=_SERIALIZE_ZDICT)
        jsonstr = decomp.decompress(b).decode("utf-8")
        return cls._from_json(json.loads(jsonstr))
    #enddef

    # # XXX: Temporary implementation for testing.
    # @classmethod
    # def from_tinfo(cls, tinfo, **kwargs):
    #     return WilType()
    # #enddef

    #
    # _build_from_tinfo
    # 
    # :param ignore_toplevel_ref: Do not build a NamedRef for the top-level
    #                             tinfo if it has a type name. This is useful
    #                             when trying to build the contents of a type
    #                             that has an assigned name.
    #
    @classmethod
    def _build_from_tinfo(cls, tinfo,
                          search=None,
                          make_refs=True,
                          ignore_toplevel_ref=False,
                          use_forward_refs=False,
                          **kwargs):

        kwargs["make_refs"] = make_refs
        kwargs["use_forward_refs"] = use_forward_refs
        # Note: ignore_toplevel_ref is not passed to recursive call.
        
        # print("_build_from_tinfo: kwargs = {!r}".format(kwargs))
        if search != None:
            for subcls in util.get_all_subclasses(cls):
                if subcls.__name__ == search:
                    if "_build_from_tinfo" in subcls.__dict__:
                        return subcls._build_from_tinfo(tinfo, **kwargs)
                    else:
                        return None
                    #endif
                #endif
            #endfor
            return None
        else:
            subclasses = util.get_all_subclasses(cls)
            subclasses.remove(NamedRef)
            for subcls in [NamedRef] + subclasses:
                if subcls == NamedRef and (not make_refs or ignore_toplevel_ref):
                    # print("Ignoring NamedRef.")
                    continue
                #endif
                if not "_build_from_tinfo" in subcls.__dict__: continue
                # print("Trying {!r}".format(subcls))
                ty = subcls._build_from_tinfo(tinfo, **kwargs)
                if isinstance(ty, cls):
                    # print("\tsucceeded: {!r}".format(ty))
                    return ty
                #endif
                # print("\tfailed.")
            #endfor
            return None
        #endif
    #enddef

    @classmethod
    def from_tinfo(cls, tinfo, ignore_toplevel_ref=False, **kwargs):
        ty = cls._build_from_tinfo(tinfo, ignore_toplevel_ref=ignore_toplevel_ref, **kwargs)
        if isinstance(ty, cls):
            return ty
        else:
            raise TInfoConversionExn("Could not convert tinfo_t to WilType: {}".format(tinfo))
        #endif
    #enddef
    
#enddef

class Primitive(WilType):
    '''Primitive type.

    All primitive types are of this class.
    '''

    def __init__(self, name, sz, is_signed, c_name, tinfo, **kwargs):
        self._tinfo = tinfo
        self._name = name
        self._size = sz
        self._is_signed = is_signed
        self._c_name = c_name
        super().__init__(**kwargs)
    #enddef

    def to_tinfo(self, **kwargs): return self._tinfo

    def is_signed(self): return self._is_signed

    @property
    def bytesize(self): 
        if self._size == None: raise NoSizeExn("Primitive does not have a size")
        return self._size 
    #enddef

    def __str__(self): return self._c_name

    def __repr__(self):
        return "<Primitive[{}]>".format(self._name)
    #enddef

    @classmethod
    def _build_from_tinfo(cls, tinfo, **kwargs):
        for (test, ty) in cls._tinfo_test_funcs:
            if test(tinfo): return ty
        #endfor
        # Special case for 'int' and 'unsigned int'.
        if tinfo.is_int():
            sz = tinfo.get_size()
            if sz == 2: return Int16
            elif sz == 4: return Int32
            elif sz == 8: return Int64
        elif  tinfo.is_uint():
            sz = tinfo.get_size()
            if sz == 2: return UInt16
            elif sz == 4: return UInt32
            elif sz == 8: return UInt64
        else:
            return None
        #endif
    #enddef

    def _build_properties_json(self):
        return {"t" : self._name}
    #enddef

    @classmethod
    def _from_properties_json(cls, props):
        name = str(props["t"])
        if not name in _PRIMITIVE_MAP.keys():
            raise UnserializeExn("Unknown primitive {}".format(name))
        #endif
        return getattr(sys.modules[__name__], name)
    #enddef

    @classmethod
    def get_by_name(cls, name):
        thismod = sys.modules[__name__]
        return getattr(thismod, name)
    #enddef
    
#endclass

# Create all primitive types.
def _create_primitives():

    thismod = sys.modules[__name__]

    Primitive._tinfo_test_funcs = []
    
    for (tyname, (sz, signed, c_name, ida_bt_ty, ida_is_test)) \
        in _PRIMITIVE_MAP.items():
        tinfo = idaapi.tinfo_t()
        tinfo.create_simple_type(ida_bt_ty)
        ty = Primitive(tyname, sz, signed, c_name, tinfo)
        setattr(thismod, tyname, ty)
        Primitive._tinfo_test_funcs.append((ida_is_test, ty))
    #endfor
   
#enddef
_create_primitives()

class Pointer(WilType):
    '''Pointers.'''

    def __init__(self, target_ty, **kwargs):
        TYPECHECK(target_ty, WilType)
        self._target_ty = target_ty
        super().__init__(**kwargs)        
    #enddef

    @property
    def target(self): return self._target_ty

    @property
    def bytesize(self): return Sizes.ADDR

    @property
    def components(self): return (self._target_ty,)

    def to_tinfo(self, **kwargs):
        tinfo = idaapi.tinfo_t()
        tinfo.create_ptr(self.target.to_tinfo(**kwargs))
        return tinfo
    #enddef
       
    @classmethod
    def _build_from_tinfo(cls, tinfo, **kwargs):
        if tinfo.is_ptr():
            target_tinfo = tinfo.get_pointed_object()
            return cls(WilType.from_tinfo(target_tinfo, **kwargs))
        else:
            return None
        #endif
    #enddef

    def _build_properties_json(self):
        return {"t" : self.target._to_json()}
    #enddef

    @classmethod
    def _from_properties_json(cls, obj):
        return cls(WilType._from_json(obj["t"]))
    #enddef
    
#endclass

# XXX: Support shifted pointers

class Function(WilType):
    '''Function type.
    '''
    
    class CC(enum.Enum):
        '''Function calling convention.'''
        CDECL = idaapi.CM_CC_CDECL
        ELLIPSIS = idaapi.CM_CC_ELLIPSIS
        STDCALL = idaapi.CM_CC_STDCALL
        PASCAL = idaapi.CM_CC_PASCAL
        FASTCALL = idaapi.CM_CC_FASTCALL
        THISCALL = idaapi.CM_CC_THISCALL
        USERCALL = idaapi.CM_CC_SPECIAL
        USERPURGE = idaapi.CM_CC_SPECIALP
        UNKNOWN = idaapi.CM_CC_UNKNOWN
        # XXX: vararg related CCs?
    #endclass

    LOC = enum.Enum("LOC", ("REG", "STACK"))

    @classmethod
    def LOC_REG(cls, value): return (cls.LOC.REG, value)

    @classmethod
    def LOC_STACK(cls, value): return (cls.LOC.STACK, value)
    
    def __init__(self, args, ret_ty, 
                 cc = CC.CDECL,
                 storeinfo = None,
                 spoilinfo = None,
                 **kwargs):
        '''Create a new Function type.
        
        :param args: arguments, a list of (name, type) tuples
        :param rey_ty: return type
        :param cc: calling convention, see `Function.CC`.
        :param storeinfo: 2-tuple of the form `(args_store, ret_store)`, where:

           - `args_store` is a dict mapping argument names to argument locations
             (see below for more information about locations)
           - `ret_store` is the name of the register holding the return value, or
             None if there is no return value.
        :param spoilinfo: list of register names, indicating registers that are
           spoiled by this function.

        An argument location is a 2-tuple of the form `(loc_spec, loc_value)`,
        where `loc_spec` is a `Function.LOC` enum, and `loc_value` is either a
        register name or a stack offset, depending on `loc_spec`. The helper
        functions `LOC_REG` and `LOC_STACK` can be used to generate argument
        location values.

        Argument locations should only be specified when the USERCALL or
        USERPURGE calling conventions are used, in which case a location
        should be specified for every argument of the function.
        '''        

        self._args = args
        self._ret_ty = ret_ty
        self._storeinfo = storeinfo
        self._cc = cc
        self._spoilinfo = spoilinfo

        # XXX: Should we do some sanity checks here first, instead of in to_tinfo()?

        super().__init__(**kwargs) 
        
    #enddef

    def __del__(self):
        for (_, ty) in self._args: ty._unregister_container(self)
        self._ret_ty._unregister_container(self)
    #enddef
    
    @property
    def args(self): return self._args

    @property
    def ret_ty(self): return self._ret_ty
   
    @property
    def components(self):
        return tuple(set((ty for (_, ty) in self._args)).union((self._ret_ty,)))
    #enddef
    
    def to_tinfo(self, **kwargs):
        
        func_data = idaapi.func_type_data_t()

        for (name, ty) in self._args:
            arg = func_data.push_back()
            arg.name = name
            arg.type = ty.to_tinfo(**kwargs)
        #endfor

        func_data.rettype = self._ret_ty.to_tinfo(**kwargs)

        if self._storeinfo != None:

            if not self._cc in (Function.CC.USERPURGE, Function.CC.USERCALL):
                raise InvalidCallingConventionExn(
                    "Custom storeinfo requires a user calling convention.")
            #endif
            
            (args_store, ret_store) = self._storeinfo
            # Assign store location to arguments.
            for arg in func_data:
                if not arg.name in args_store:
                    raise InvalidStoreInfoExn("Missing storeinfo for argument {}".format(arg.name))
                #endif

                (loc_spec, loc_value) = args_store[arg.name]
                if loc_spec == self.LOC.REG:
                    reg = idaapi.str2reg(loc_value)
                    if reg == -1: 
                        raise InvalidStoreInfoExn("Invalid register: {}".format(loc_value))
                    #endif
                    arg.argloc.set_reg1(reg)
                    
                elif loc_spec == self.LOC.STACK:
                    arg.argloc.set_stkoff(int(loc_value))

                else:
                    raise InvalidStoreInfoExn("Invalid location specifier.")
                #endif

            #endfor

            # Set store location for return value.
            if ret_store != None:
                reg = idaapi.str2reg(ret_store)
                if reg == -1: raise InvalidStoreInfoExn(ret_store)
                func_data.retloc.set_reg1(reg)
            #endif

        elif self._cc in (Function.CC.USERPURGE, Function.CC.USERCALL):
            raise InvalidStoreInfoExn("Missing storeinfo for userpurge/usercall calling convention.")
        #endif
        
        if self._spoilinfo != None:
            for regname in self._spoilinfo:
                reginfo = func_data.spoiled.push_back()
                if not idaapi.parse_reg_name(reginfo, regname):
                    raise InvalidSpoilInfoExn(regname)
                #endif
            #endfor
        #endif

        # Note: Making use of internal invariant that value of our CC enum
        # is the value of the corresponding IDA CM_CC enum.
        func_data.cc = self._cc.value

        tinfo = idaapi.tinfo_t()
        rv = tinfo.create_func(func_data)
        if not rv: raise FunctionExn("Error constructing function tinfo.")

        return tinfo
        
    #enddef
   
    @classmethod
    def _build_from_tinfo(cls, tinfo, **kwargs):
        
        if not tinfo.is_func(): return None

        func_data = idaapi.func_type_data_t()

        if not tinfo.get_func_details(func_data):
            raise TInfoConversionExn("Could not get tinfo_t function details.")
        #endif

        args = [
            (arg.name, WilType.from_tinfo(arg.type, **kwargs))
            for arg in func_data
        ]
        
        ret_ty = WilType.from_tinfo(func_data.rettype, **kwargs)

        cc = cls.CC(func_data.cc & idaapi.CM_CC_MASK)

        if cc in (cls.CC.USERCALL, cls.CC.USERPURGE):
            # Custom calling convention, need to manually set storeinfo.
            argsstore = {}
            for arg in func_data:
                argloc = arg.argloc
                if argloc.is_reg():
                    regname = idaapi.get_reg_name(arg.argloc.reg1(), arg.type.get_size())
                    if regname == None: raise TInfoConversionExn("Unknown argument store register location.")
                    argsstore[arg.name] = cls.LOC_REG(regname)
                elif argloc.is_stkoff():
                    argsstore[arg.name] = cls.LOC_STACK(arg.argloc.stkoff())
                else:
                    raise UnimplementedExn("Cannot handle non-register non-stack argument location.")
                #endif
            #endfor

            if ret_ty != Unit:
                if func_data.retloc.is_reg():
                    retstore = idaapi.get_reg_name(func_data.retloc.reg1(),
                                                   func_data.rettype.get_size())
                    if retstore == None: raise TInfoConversionExn("Unknown return value register location.")
                else:
                    raise UnimplementedExn("Cannot handle non-register return location.")
                #endif
            else:
                retstore = None
            #endif

            storeinfo = (argsstore, retstore)

        else:

            storeinfo = None
            
        #endif

        spoilinfo = []
        for ri in func_data.spoiled:
            regname = idaapi.get_reg_name(ri.reg, ri.size)
            if regname == None: raise TInfoConversionExn("Unknown spoiled register")
            spoilinfo.append(regname)
        #endfor

        f = Function(args, ret_ty, cc, storeinfo, spoilinfo)

        return f
    
    #enddef

    def _build_properties_json(self):
        return {
            "args" : [(n, ty._to_json()) for (n, ty) in self._args],
            "retty" : self._ret_ty._to_json(),
            "cc" : self._cc.value,
            "storeinfo" : ([(n, (l[0].value, l[1])) for (n, l) in self._storeinfo[0]], self._storeinfo[1]) if self._storeinfo != None else None,
            "spoilinfo" : self._spoilinfo
        }
    #enddef

    @classmethod
    def _from_properties_json(cls, obj):
        if obj["storeinfo"] != None:
            (args_store_j, ret_store_j) = obj["storeinfo"]
            # XXX: The below doesn't seem to do anything, so commented it
            # out. Might have been old code that I forgot to remove.            
            # (loc_spec_j, loc_value_j) = args_store_j
            args_store = [(n, (LOC(l[0]), l[1]))
                          for (n, l) in args_store_j]
            storeinfo = (args_store, ret_store_j)
        else:
            storeinfo = None
        #endif
        return cls(
            [(n, WilType._from_json(jty)) for (n, jty) in obj["args"]],
            WilType._from_json(obj["retty"]),
            cc = Function.CC(obj["cc"]),
            storeinfo = storeinfo,
            spoilinfo = obj["spoilinfo"]
        )
    #enddef

    
#endclass


# XXX: Method type? Not sure if necessary?

class Array(WilType):
    '''Fixed-capacity arrays of other types.'''

    # XXX: Write unit tests!
    
    def __init__(self, elem_ty, capacity, **kwargs):
        TYPECHECK(elem_ty, WilType)
        self._elem_ty = elem_ty
        self._capacity = capacity
        super().__init__(**kwargs)
    #enddef

    @property
    def elem_ty(self): return self._elem_ty

    @property
    def capacity(self): return self._capacity

    @property
    def bytesize(self): return self._elem_ty.bytesize * self._capacity

    @property
    def components(self): return (self._elem_ty,)

    def to_tinfo(self, **kwargs):
        atd = idaapi.array_type_data_t()
        atd.elem_type = self.elem_ty.to_tinfo(**kwargs)
        atd.nelems = self.capacity
        tinfo = idaapi.tinfo_t()
        tinfo.create_array(atd)
        return tinfo
    #enddef

    @classmethod
    def _build_from_tinfo(cls, tinfo, **kwargs):
        if not tinfo.is_array(): return None
        elem_tinfo = tinfo.get_array_element()
        capacity = tinfo.get_array_nelems()
        return cls(WilType.from_tinfo(elem_tinfo, **kwargs), capacity)
    #enddef

    def _build_properties_json(self):
        return {"e" : self.elem_ty._to_json(), "c" : self.capacity}
    #enddef

    @classmethod
    def _from_properties_json(cls, obj):
        return cls(WilType._from_json(obj["e"]), obj["c"])
    #enddef
    
#endclass

class NamedRef(WilType):
    '''Reference to a named type. A reference can be declared as a forward
    reference, which means its resolution is delayed till use (or
    =resolve_forward_ref()= is called).
    '''
    
    def __init__(self, tyname, forward=False, **kwargs):
        super().__init__(**kwargs)
        if forward:
            self._forward_name = str(tyname)
        else:
            self._setup_tyname(tyname)
        #endif
    #enddef

    def _setup_tyname(self, tyname_str):
        try:
            self._tyname = module.current().types[tyname_str]
        except KeyError:
            raise UnknownTypeNameExn("No type with name '{}' exists in the context.".format(tyname_str))
        #endtry

        # We depend on the invariant that if a qname is part of the typename
        # context, then an idaname matching that qname already exists.
        self._tyname.add_event_observer(self._tyname_observer)
    #enddef

    def is_forward_ref(self): return hasattr(self, "_forward_name")
    
    def resolve_forward_ref(self):
        if self.is_forward_ref():
            self._setup_tyname(self._forward_name)
            del self._forward_name
        #endif
    #enddef
    
    @property
    def tyname(self):
        self.resolve_forward_ref()
        return self._tyname
    #enddef
    
    @property
    def target(self):
        self.resolve_forward_ref()
        return self._tyname.entity
    #enddef
    
    def to_tinfo(self, **kwargs):
        self.resolve_forward_ref()
        ti = idaapi.tinfo_t()
        ti.get_named_type(idaapi.cvar.idati, self._tyname.fullname)
        return ti
    #enddef

    def _tyname_observer(self, ev):
        if isinstance(ev, qname.EntityChangeEvent):
            self.emit_event(RefChangedEvent, self.tyname, self.target)
        #endif
    #enddef

    @classmethod
    def _build_from_tinfo(cls, tinfo,
                          use_forward_refs=False,
                          **kwargs):
        idaname = tinfo.get_type_name()
        if idaname != None:
            return cls(idaname, forward=use_forward_refs)
        else:
            return None
        #endif
    #enddef

    def _build_properties_json(self):
        self.resolve_forward_ref()
        return {"n" : self._tyname.fullname}
    #enddef

    @classmethod
    def _from_properties_json(cls, obj):
        return cls(obj["n"])
    #enddef

    
#enddef

class ExtendedType(WilType):
    '''Base class of all types that have extra type information which can't be
    stored within a tinfo object.

    Note that an ExtendedType can be polymorphic, in which case a tinfo cannot
    be generated from it, and thus the properties here cannot be accessed.

    '''
    
    def __init__(self,
                 typename=None,
                 transient=True,
                 **kwargs):

        super().__init__(**kwargs)

        # This needs to stay True, even if the transient argument is set,
        # until the type has been fully persisted.
        self._is_transient = True

        if not transient:
            self.make_persistent(typename)
        #endif
            
    #enddef

    def make_persistent(self, idaname=None, **kwargs):
        # Add to context.
        DBG("Called make_persistent on {!r}:".format(self))
        if module.current().types.contains(idaname):
            DBG("\tUpdating existing type name.")
            module.current().types.update(idaname, self)
        else:
            DBG("\tAdding a new type name.")
            module.current().types.add(idaname, self)
        #endif
    #enddef

    # This function gets called by the type context when it has added the type
    # to the context, thus making it persistent.
    def _mark_as_persistent(self, ordinal, idaname):
        DBG("Marking type {!r} as persistent, ordinal={:d}, idaname={}".format(self, ordinal, idaname))
        self._type_ordinal = ordinal
        self._idaname = idaname
        self._is_transient = False
    #enddef

    # This function gets called by the type context when a previously
    # persistent type gets removed from the context, usually because it was
    # replaced by another type.
    def _mark_as_transient(self):
        DBG("Marking type {!r} as transient.".format(self))
        del self._type_ordinal
        del self._idaname
        self._is_transient = True
    #enddef
    
    @property
    def is_transient(self): return self._is_transient

    @property
    def ordinal(self):
        self.assert_mono()
        return self._type_ordinal
    #enddef

    @property
    def idaname(self):
        self.assert_mono()
        return self._idaname
    #enddef

    @idaname.setter
    def idaname(self, new_idaname):
        self._idaname = new_idaname
    #enddef
    
    # This must be defined by subclasses.
    def to_base_tinfo(self, **kwargs):
        raise UnimplementedExn()
    #enddef
    
    def to_tinfo(self, make_persistent=True, **kwargs):
        if self._is_transient:
            if not make_persistent:
                # Return immediately with base tinfo.
                return self.to_base_tinfo(**kwargs)
            else:
                # Make persistent with no specific idaname, will cause an
                # automatically-generated name to be used.
                self.make_persistent(None, **kwargs)
            #endif
        #endif
        
        tinfo = idaapi.tinfo_t()
        # XXX: Check for errors!
        tinfo.get_named_type(idaapi.cvar.idati, self._idaname)
        return tinfo
    #enddef
   
    @classmethod
    def _build_from_tinfo(cls, tinfo, **kwargs):

        idaname = tinfo.get_type_name()
        tyctx = module.current().types

        if idaname != None and idaname in tyctx:
            ty = tyctx[idaname].entity
            if not isinstance(ty, cls):
                raise TInfoConversionExn("Type {!r} in context is not an extended type.".format(ty))
            #endif
            return ty
        else:
            return None
        #endif

    #enddef

    def _build_properties_json(self):
        if self.is_transient:
            return {"transient" : True}
        else:
            return {"transient" : False, "n" : self._idaname}
        #endif
    #enddef

    @classmethod
    def _from_properties_json(cls, obj):
        return cls(
            transient=obj["transient"],
            typename=obj["n"] if not obj["transient"] else None
        )
    #enddef

    @classmethod
    def _build_subclass_from_properties_json(cls, obj, subcls, *args, **kwargs):
        return subcls(*args, **kwargs,
                      transient=obj["transient"],
                      typename=obj["n"] if not obj["transient"] else None)
    #enddef
    
#endclass

# XXX: To implement in the future, this is just a placeholder.
# class Ins(ExtendedType):

#     def __init__(self, tvar_idx, replace_ty, body_ty, **kwargs):
#         super().__init__(**kwargs)
#         self._tvar_idx = tvar_idx
#         self._replace_ty = replace_ty
#         self._body_ty = body_ty
#     #enddef

#     def beta_reduce(self):
#         # XXX: Implement
#         return self
#     #enddef

#     def _to_base_tinfo(self):
#         return self.beta_reduce().to_tinfo()
#     #enddef

#     def _to_properties_json(self):
#         return {
#             "i" : self._tvar_idx,
#             "r" : self._replace_ty._to_json(),
#             "b" : self._body_ty._to_json()
#         }
#     #enddef

#     @classmethod
#     def _from_properties_json(cls, obj):
#         return cls(obj["i"],
#                    WilType._from_json(obj["r"]),
#                    WilType._from_json(obj["b"]))
#     #enddef

# #endclass

class UDTBackedType(ExtendedType):
    '''Abstract base class for all types that, when reduced, yield an IDA
    user-defined type (UDT). The components of the type are referred to as
    'elements'.

    This class defines helper functions for creating and maintaining the UDT.
    '''

    def __init__(self, **kwargs):
        # if self.is_mono:
        #     (self._base_tinfo, self._bytesize) = self._build_base_tinfo()
        # #endif

        super().__init__(**kwargs)
        
    #enddef

    def to_base_tinfo(self, **kwargs):
        self.assert_mono()
        (self._base_tinfo, self._bytesize) = self._build_base_tinfo(**kwargs)
        return self._base_tinfo
    #enddef

    # Must be overriden by subclasses.
    @property
    def components(self): raise UnimplementedExn

    @property
    def bytesize(self):
        if not hasattr(self, "_bytesize"):
            (self._base_tinfo, self._bytesize) = self._build_base_tinfo()
        #endif
        return self._bytesize
    #enddef
    
    # Must be overriden by subclasses to create the tinfo object.
    def _build_base_tinfo(self, **kwargs): raise UnimplementedExn

    @classmethod
    def _generate_udt_tinfo(cls, elem_spec, is_union,
                            requested_size=None,
                            to_tinfo_kwargs=None):
        '''This function generates a UDT `tinfo_t` object.

        `elem_spec` specifies the elements of the UDT, and is a list of
        3-tuples of the form `(offset, name, ty)`, where `name` is the name of
        the element, `ty` is the type of the element, and `offset` is the
        position within the composite where the element is located, if
        applicable. If `offset` is a negative value, then the UDT is assumed
        to be that of a structure, and the offset is automatically calculated
        based on the module's configuration. The list *must* be pre-sorted
        by offsets, for non-automatically-calculated offsets.

        `is_union` determines whether or not the UDT is a union.

        `requested_size`, if provided, indicates the total size of the
        resultant type; IDA will pad the object as required.

        `elem_spec` can be empty, indicating a UDT with no elements. However,
        this requires `requested_size` to be provided, in order to know what
        size the UDT should be. Otherwise, an exception will be raised.

        `to_tinfo_kwargs` is passed as the kwargs for calls to to_tinfo.

        '''
        
        udt_data = idaapi.udt_type_data_t()

        prev_offset = 0
        prev_size = 0
        for (offset, name, ty) in elem_spec:
            # Note: Internally, IDA refers to UDT elements as members. Don't
            # confuse this with class members!
            udt_memb = udt_data.push_back()

            if offset < 0:
                offset = cls._auto_calc_offset(prev_offset + prev_size, ty)
            elif offset < prev_offset:
                raise InvalidUDTSpecExn("Specification offsets must be in asecending order.")
            #endif
           
            # Note: member offset is given in bits
            udt_memb.offset = offset * 8
            udt_memb.type = ty.to_tinfo()
            udt_memb.size = udt_memb.type.get_size() << 3
            udt_memb.name = name
            udt_memb.cmt = ""

            prev_offset = offset
            prev_size = udt_memb.type.get_size()
                        
        #endfor

        udt_data.is_union = is_union
        
        tinfo = idaapi.tinfo_t()

        if is_union:
            tinfo.create_udt(udt_data, idaapi.BTF_UNION)
        else:
            if requested_size == None:

                if len(elem_spec) == 0:
                    raise InvalidUDTSpecExn("Spec is empty but no size requested.")
                #endif
                
                # Calculate the size based on the last element.
                last_udt_memb = list(udt_data)[-1]
                requested_size = (last_udt_memb.offset + last_udt_memb.size) >> 3
                # XXX: Calculate any additional padding required for whole
                # structure alignment.               

            #endif

            udt_data.total_size = requested_size
            tinfo.create_udt(udt_data, idaapi.BTF_STRUCT)

            calc_rv = tinfo.calc_udt_aligns()

            if not calc_rv:
                raise InvalidUDTSpecExn("Either element specification or size was invalid.")
            #endif

        #endif

        # Now that the tinfo has been created, use it to determine the actual
        # size of this type.
        udt_data = idaapi.udt_type_data_t()
        # XXX: Handle failure here!
        tinfo.get_udt_details(udt_data)

        sz = udt_data.total_size

        if not is_union and sz != requested_size:
            raise InvalidUDTSizeExn("Resultant size does not match specification.")
        #endif

        # Note: this includes the gaps introduced by IDA
        calced_offsets = dict([
            (str(udt_memb.name), udt_memb.offset >> 3)
            for udt_memb in udt_data
        ])
       
        return (tinfo, sz, calced_offsets)

    #enddef

    @staticmethod
    def _auto_calc_offset(start_offset, ty):
        modinfo = module.current().info

        # XXX: Test more, and add more conditions if necessary.
       
        if isinstance(ty, Primitive):
            if modinfo["8align4"] and ty._name in ("Int64", "UInt64", "Double"):
                align = 4
            elif not modinfo["bigarg_align"] and ty._name in ("Int64", "Int128", "UInt64", "UInt128", "Double", "LDouble"):
                align = 4
            else:
                align = ty.bytesize
        elif isinstance(ty, Pointer):
            align = Sizes.ADDR
        else:
            align = 4
        #endif

        return start_offset + ((align - (start_offset % align)) % align)
        
    #enddef

    @staticmethod
    def _elem_spec_from_tinfo(tinfo, **kwargs):

        udt_data = idaapi.udt_type_data_t()
        tinfo.get_udt_details(udt_data)

        elems = [
            (udt_memb.offset >> 3,
             str(udt_memb.name),
             WilType.from_tinfo(udt_memb.type, **kwargs))
            for udt_memb
            in udt_data
            if udt_memb.name != "gap{:X}".format(udt_memb.offset >> 3)]

        return (elems, udt_data.total_size, udt_data.is_union)

    #enddef
    
#endclass

class Struct(UDTBackedType):
    '''C-style structs, i.e just a collection of fields. Distinct from classes.

    Note: A C++ struct with associated methods will be considered a Class, not
    a Struct.
    '''

    # Values of this enum map to index position of the specifier in the field tuple.
    class FIELDSPEC(enum.Enum):
        OFFSET = 0,
        NAME = 1,
        TYPE = 2
    #endclass
    
    def __init__(self, fields, total_size = None,
                 **kwargs):
        '''
        :param fields: A list of 3-tuples of the form `(offset, name, ty)`.
            `offset` is the offset from the base of the struct. This list is
            identical to the one expected by `UDTBackedType._generate_udt_tinfo()`.
        :param total_size: Size of this struct in bytes. Will add padding bytes
            if necessary.
        '''
        self._fields = fields
        self._total_size = total_size
        super().__init__(**kwargs)
    #enddef

    @property
    def fields(self): return tuple(self._fields)

    @property
    def total_size(self): return self._total_size
    
    @property
    def components(self): return tuple(set((ty for (_, _, ty) in self._fields)))

    def validate(self):
        try:
            self.to_base_tinfo()
        except (InvalidUDTSpecExn, InvalidUDTSpecExn) as e:
            raise InvalidFieldsExn("Invalid fields specification") from e
        #endtry
    #enddef            
                          
    def _build_base_tinfo(self, **kwargs):
        (tinfo, sz, calced_offsets) = self._generate_udt_tinfo(
            self._fields,
            is_union=False,
            requested_size=self._total_size,
            to_tinfo_kwargs=kwargs
        )
        self._calced_offsets = calced_offsets
        return (tinfo, sz)
    #enddef

    def _ensure_calced_offsets(self):
        if not hasattr(self, "_calced_offsets"):
            self.to_base_tinfo()
        #endif
    #enddef
    
    def get_calced_field_info(self):
        '''Returns a list of 4-tuples of the form `(calced_offset, offset, name,
        ty)`, where `calced_offset` is the actual calculated offset of the
        field, and the other values are the same as in `self.fields`.
        '''
        self._ensure_calced_offsets()
        return [
            (self._calced_offsets[name], offset, name, ty)
            for (offset, name, ty)
            in self._fields
        ]
    #enddef

    def get_calced_offset_of_field(self, field):
        self._ensure_calced_offsets()
        return self._calced_offsets[field]
    #enddef
    
    def find_field_at_offset(self, offset, strict=True):
        '''Returns a 3-tuple (offset, name, ty) of the field at the specified offset,
        or raises InvalidOffsetExn if no field is found at that offset. If
        <strict> is True, the offset must refer to the start of the
        field. Otherwise, this function will find fields as long as the offset
        lies within the extents of the field.
        '''
        if offset >= self.bytesize:
            raise InvalidOffsetExn("Offset beyond size of Struct")
        #endif

        calced_fields = self.get_calced_field_info()
        calced_fields.sort(key=lambda f: f[0])
        
        # Doing an inefficient linear search right now because the number of
        # fields is not likely to be large.
        for (calced_offset, _, name, ty) in calced_fields:
            if calced_offset < offset:
                if not strict and (offset < calced_offset + ty.bytesize):
                    # Offset is within the current field.
                    return (calced_offset, name, ty)
                else:
                    continue
                #endif
            elif calced_offset == offset:
                    return (calced_offset, name, ty)
            elif calced_offset > offset:
                raise InvalidOffsetExn("No field found at this offset")
            #endif
        #endif
    #enddef    

    def is_safe_to_add_field_at_offset(self, offset, ty):
        '''Returns True iff adding a field of type `ty` at offset `offset`
        will not overlap any existing fields.
        '''
        calced_fields = self.get_calced_field_info()
        calced_fields.sort(key=lambda f: f[0])

        range_start = offset
        range_end = offset + ty.bytesize
        
        for (calced_offset, _, _, ty) in calced_fields:
            field_start = calced_offset
            field_end = calced_offset + ty.bytesize
            if (range_end <= field_start) or (range_start >= field_end):
                continue
            else:
                return False
            #endif
        #endfor
        return True
    #enddef
    
    def find_field_by_name(self, field_name):
        # XXX: Should we provide the calculated offset of the field as well?
        
        # Doing an inefficient linear search right now because the number of
        # fields is not likely to be large.
        for (offset, name, ty) in self._fields:
            if name == field_name:
                return (offset, name, ty)
            #endif
        #endfor

        raise InvalidFieldNameExn("No field with this name.")

    #enddef    

    def has_field_with_name(self, field_name):
        for (_, n, _) in self._fields:
            if field_name == n: return True
        #endfor
        return False
    #enddef
    
    def extend(self, new_fields, new_size=None):

        '''Returns a new, transient Struct type that consists of the fields of this
        type extended with the additional fields in `new_fields`. 
        '''

        final_fields = []

        pos = 0
        for (offset, name, ty) in self._fields:
            while pos < len(new_fields) and new_fields[pos][0] < offset:
                final_fields.append(new_fields[pos])
                pos += 1
            #endwhile
            final_fields.append((offset, name, ty))
        #endfor

        if pos < len(new_fields):
            final_fields += new_fields[pos:]
        #endif

        if new_size == None and self._total_size != None:
            if len(final_fields) > 0 and (final_fields[-1][0] + final_fields[-1][2].bytesize) >= self._total_size:
                # The new fields extend beyond the previously set size. Leave
                # new_size as None, so the size gets recalculated.
                pass
            else:
                new_size = self._total_size
            #endif
        #endif
        
        return self.__class__(final_fields, total_size=new_size, transient=True)
        
    #enddef
    
    def remove_field(self, field_idx, new_size=None):

        final_fields = self._fields[:field_idx] + self._fields[field_idx+1:]

        if new_size != None:
            total_size = new_size
        else:
            total_size = self._total_size
        #endif
        
        return self.__class__(final_fields, total_size=total_size, transient=True)        

    #enddef
    
    def modify(self, field_idx, field_spec, value,
               preserve_size=True):
        '''Returns a new, transient Struct type that consists of the fields of
        this type, but with the field at index `field_idx` modified such that
        the field specifier `field_spec` has new value `value`. If
        `preserve_size` is True and the modification causes the resultant size
        to exceed the previously defined total size, raise an
        Exception. Otherwise, total size will be adjusted if necessary.
        '''
       
        new_fields = list(self.fields)
        new_size = self._total_size if preserve_size else None
        recalc_offset = False
        (offset, name, ty) = new_fields[field_idx]
        match field_spec:
            case Struct.FIELDSPEC.OFFSET:
                offset = int(value)
                # Don't recalculate if the offset is negative, i.e. automatic.
                if offset >= 0: recalc_offset = True
            case Struct.FIELDSPEC.NAME:
                name = str(value)
            case Struct.FIELDSPEC.TYPE:
                ty = value
            case _:
                raise InvalidFieldSpecExn("Unknown field specifier {!r}".format(field_spec))
        #endmatch

        if self._total_size != None and offset + ty.bytesize > self._total_size:
            if preserve_size:
                raise CannotPreserveSizeExn("Struct modification for field at index {:d} to {!r} cannot preserve total size of {:d}.".format(field_idx, (offset, name, ty), self._total_size))
            else:
                # Modified offset exceeds current size, so don't set
                # total_size, let it be recalculated.
                new_size = None
            #endif
        else:
            new_size = self._total_size
        #endif

        if recalc_offset:
            # This was an offset change, we might need to reposition the field
            # in the list to maintain sorted order. To do this easily, we
            # generate a temp Struct type without the modified field, and then
            # use Struct.extend() to add the modified field in the right
            # position.
            del new_fields[field_idx]
            temp = self.__class__(new_fields, total_size=new_size, transient=True)
            return temp.extend([(offset, name, ty)])
        else:
            # Set to new values directly.
            new_fields[field_idx] = (offset, name, ty)
        #endif

        return self.__class__(new_fields, total_size=new_size, transient=True)
                
    #enddef

    def modify_size(self, new_size):
        if new_size != None:
            calced_fields = self.get_calced_field_info()
            (last_offset, _, _, last_ty) = calced_fields[-1]
            if new_size < last_offset + last_ty.bytesize:
                raise InvalidSizeExn("Modified size of {:d} is too small; field specification requires minimum size of {:d}.".format(new_size, last_offset + last_ty.bytesize))
            #endif
        #endif
        return self.__class__(self.fields, total_size=new_size, transient=True)
    #enddef
    
    
    def _build_properties_json(self):
        spec = [(offset, name, ty._to_json()) for (offset, name, ty) in self._fields]
        return {"spec" : spec, "sz": self._total_size}
    #enddef

    @classmethod
    def _from_properties_json(cls, obj):
        spec = [
            (offset, name, WilType._from_json(jsonty))
            for (offset, name, jsonty)
            in obj["spec"]
        ]
        return super()._build_subclass_from_properties_json(
            obj,
            cls,
            spec,
            total_size=obj["sz"]
        )
    #enddef

    @classmethod
    def _build_from_tinfo(cls, tinfo, **kwargs):
        if not tinfo.is_udt() or tinfo.is_union(): return None
        (elem_spec, total_size, _) = cls._elem_spec_from_tinfo(tinfo, **kwargs)
        # Always return a transient extended type.
        return cls(elem_spec, total_size=total_size, transient=True)
    #enddef
    
#endclass

class Union(UDTBackedType):
    '''C-style unions.
    '''
    
    def __init__(self, alternates, **kwargs):
        '''
        :param alternates: A list of 2-tuples of the form `(name, ty)`, one
        for each possible alternate type of this union.
        '''
        self._alternates = alternates
        super().__init__(**kwargs)
    #enddef

    @property
    def alternates(self): return tuple(self._alternates)

    @property
    def components(self): return tuple(set((ty for (_, ty) in self._alternates)))

    def _build_base_tinfo(self, **kwargs):
        (tinfo, sz, _) = self._generate_udt_tinfo(
            [(0, name, ty) for (name, ty) in self._alternates],
            is_union=True,
            to_tinfo_kwargs=kwargs
        )
        return (tinfo, sz)
    #enddef

    def _build_properties_json(self):
        spec = [(name, ty._to_json()) for (name, ty) in self._alternates]
        return {"spec" : spec}
    #enddef

    @classmethod
    def _from_properties_json(cls, obj):
        alternates = [
            (name, WilType._from_json(jsonty))
            for (name, jsonty)
            in obj["spec"]
        ]
        return super()._build_subclass_from_properties_json(
            obj,
            cls,
            alternates
        )
    #enddef

    @classmethod
    def _build_from_tinfo(cls, tinfo, **kwargs):
        if not tinfo.is_udt() or not tinfo.is_union(): return None
        (elem_spec, _, _) = cls._elem_spec_from_tinfo(tinfo, **kwargs)
        # Always return a transient extended type.
        return cls([(name, ty) for (_, name, ty) in elem_spec], transient=True)
    #enddef
    
#endclass


####################
# UTILITY FUNCTIONS
####################


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

###############
# TYPE CONTEXT
###############

class TypeContextStorage(storage.Storage):
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
    #enddef

    def add(self, qns, ty):
        DINFO("TypeContextStorage.add: {!r} -> {!r}".format(qns, ty))
        self.strmap[qns] = ty.serialize()
    #enddef

    def remove(self, qns):
        DINFO("TypeContextStorage.remove: {!r}".format(qns))
        del self.strmap[qns]
    #enddef
    
    def get(self, qns): return WilType.unserialize(self.strmap[qns])
    
    def rename(self, old_qns, new_qns):
        DINFO("TypeContextStorage.rename: {!r} to {!r}".format(old_qns, new_qns))
        self.strmap[new_qns] = self.strmap[old_qns]
        del self.strmap[old_qns]
    #enddef

    def has_name(self, qns): return qns in self.strmap
    
#enddef

class TypeName(qname.QName):

    def __init__(self, *args, touched=False, **kwargs):
        super().__init__(*args, **kwargs)
        self._touched = touched
    #enddef

    def _find_ida_ordinal(self):
        ti = idaapi.tinfo_t()
        ti.get_named_type(idaapi.cvar.idati, self.fullname)
        # XXX: Check for errors
        ordinal = ti.get_ordinal()       
        return ordinal
    #enddef

    @property
    def is_touched(self): return self._touched
    
    def mark_touched(self, touched):
        self._touched = touched
    #enddef
    
    # Updates IDA's local type library with the type associated with this name.
    def _update_ida(self):

        # Do not update if type is untouched.
        if not self.is_touched: return

        ty = self.entity
        if isinstance(ty, ExtendedType):
            # Always use to_base_tinfo() to update from extended types
            tinfo = ty.to_base_tinfo().copy()
        else:
            tinfo = ty.to_tinfo().copy()
        #endif

        ordinal = self._find_ida_ordinal()

        # Replace the tinfo.
        tinfo.set_numbered_type(idaapi.cvar.idati, ordinal, idaapi.NTF_REPLACE, self.fullname)

        if isinstance(ty, ExtendedType) and ty.is_transient:
            # Mark extended type as persistent now that it has an associated IDA type.
            ty._mark_as_persistent(tinfo.get_ordinal(), tinfo.get_type_name())
        #endif
    #enddef  

    # Updates storage with the type associated with this name.
    def _update_storage(self):
        self._ctx._storage.add(self.fullname, self.entity)
    #enddef
    
#endclass

class TypeContext(qname.Context):

    # XXX: Code here probably doesn't work well for polymoprhic types, when we
    # add those, will need to rewrite stuff here to cater for that.
    
    STORAGE_NAME = "typing.typecontext"
    
    def __init__(self, mod, name="types"):
        super().__init__(name, qncls=TypeName)
        self._parent_module = mod
        self._storage = mod.get_storage(self.STORAGE_NAME,
                                        storage_class=TypeContextStorage)
        self.root.add_relay_event_observer(self._observer)
    #enddef

    def add(self, qns, ty,
            caused_by=None,
            touched=True,
            _do_not_create_idaname=False,            
            **kwargs):

        '''Add a new type to the typename context.
        '''

        DINFO("Adding new type {!r} to typing context, qname = {!r}:".format(ty, qns))
        
        if isinstance(ty, ExtendedType) and not ty.is_transient:
            # This type is already persistent and has a name. Link it to
            # the requested name using a NamedRef instead.
            orig_ty = ty
            ty = NamedRef(self.locate(orig_ty.idaname))
            DINFO("\tChanged type to NamedRef.")
        #endif

        if qns == None:
            # Create an automatic name.
            qn = self.auto_name()
        else:
            qn = self.locate(qns, build=True, caused_by=caused_by)
        #endif
        # Relying on the invariant here that only newly built qnames in the
        # context have no entity set.
        if qn.entity == None:
            qn.entity = ty
        else:
            raise DuplicateNameExn("Type name {} already exists in context.".format(qns))
        #endif

        # Mark typename as touched or not.
        qn.mark_touched(touched)
        
        # This should only be used internally by sync(); otherwise the
        # type context and IDA's local type library will go out of sync.
        if _do_not_create_idaname:
            DINFO("\tNot creating new IDA type, as requested.")
            return
        #endif
        
        # XXX: Should we stop here for polymorphic types?

        # Create a matching idaname in IDA's local type library.

        # Note: We rely on the invariant here that the type context is in sync
        # with the local type library, hence if a name does not appear in the
        # context, it is also not used in IDA.

        # First we get a new ordinal.
        ordinal = idaapi.alloc_type_ordinal(idaapi.cvar.idati)
        DINFO("\tAllocated ordinal for IDA type: {}".format(ordinal))

        # Temporarily populate the type associated with the ordinal/name with
        # a dummy value.
        tinfo = idaapi.tinfo_t()
        tinfo.create_simple_type(idaapi.BTF_UINT32)
        tinfo.set_numbered_type(idaapi.cvar.idati, ordinal, 0, qn.fullname)

        # Now, get the qname to update IDA, which will generate the correct
        # tinfo and replace the dummy value we put above.
        qn._update_ida()

        # Update storage as well.
        qn._update_storage()

        DINFO("\tUpdated IDA and storage.")
        
        return qn

    #enddef

    def update(self, qns, new_ty):
        qn = self.locate(qns)
        qn.entity = new_ty
    #enddef

    def remove(self, qns):
        qn = self.locate(qns)
        qn.parent.remove_child(qn.basename)
        # Further processing occurs in RemoveChild event handler _do_remove().
    #enddef
    
    def _do_remove(self, qn):
        # Mark as transient if this was an ExtendedType
        if isinstance(qn.entity, ExtendedType):
            qn.entity._mark_as_transient()
        #endif

        # Remove from storage
        self._storage.remove(qn.fullname)
        # Remove from IDA type library
        ordinal = idaapi.get_type_ordinal(idaapi.cvar.idati, qn.fullname)
        idaapi.del_numbered_type(idaapi.cvar.idati, ordinal)
    #enddef
    
    def _do_rename(self, qn, old_name, new_name):
        # Update storage.
        self._storage.rename(old_name, new_name)
        # Update IDA type library.
        util.rename_ida_type(old_name, new_name)
        # Inform extended type about name change.
        if isinstance(qn.entity, ExtendedType):
            qn.entity._idaname = new_name
        #endif
    #enddef

    def _do_entity_change(self, qn, old_entity):

        # Ignore if this is the first time the entity is set, as we handle
        # this specifically inside add().
        if old_entity == None: return

        # Name has been modified, so mark as touched.
        qn.mark_touched(True)
        
        # Update IDA type library.
        qn._update_ida()
      
        # Update storage.
        qn._update_storage()
      
        # Do cleanup for old entity if required.
        if qn.entity != old_entity and isinstance(old_entity, ExtendedType):
            DBG("_do_entity_change: Cleaning up old entity")
            old_entity._mark_as_transient()
        #endif
            
    #enddef
   
    def _observer(self, bearing, ev):
        match ev:
            case qname.AddChildEvent(parent, childname):
                qns = parent[childname].fullname
                # XXX: Think we don't need to do anything here, since we need
                # to wait for the EntityChangeEvent to get hold of the
                # assigned type to add it to the storage. Confirm this and
                # remove this clause if so.                

            case qname.RemoveChildEvent(parent, childname):
                self._do_remove(parent[childname])
            
            case qname.RenameEvent(qn, _):
                self._do_rename(qn, ev.get_old_fullname(), qn.fullname)
                
            case qname.ChildMoveEvent(qn, _, _, _, _):
                # This event gets emitted twice, once by each parent, so we make
                # sure to only apply it once.
                old_fullname = ev.get_old_fullname()
                if self._storage.has_name(old_fullname):
                    self._do_rename(qn, old_fullname, qn.fullname)
                #endif

            case qname.EntityChangeEvent(qn, old_entity):
                self._do_entity_change(qn, old_entity)
                
        #endmatch
    #enddef

    def all_typenames(self):
        return (d
                for d
                in self.root.filter_descendents(lambda qn: isinstance(qn.entity, WilType)))
    #enddef

    def all_types(self): return (d.entity for d in self.all_typenames())
    
    def update_all_types(self):
        DINFO("Updating all types:")
        for tyname in self.all_typenames():
            DINFO("\tUpdating {}".format(tyname.fullname))
            DBG("\t\tEnsuring forward references have been resolved.")
            tyname.entity.ensure_resolve_forward_refs()
            DBG("\t\tUpdating IDA.")
            tyname._update_ida()
            DBG("\t\tUpdate storage.")
            tyname._update_storage()
        #endfor
    #enddef
    
    def sync(self):

        # The purpose of this function is to sync the type context with IDA's
        # local type library. The assumption is that when the function is
        # called, the type context and IDA are possibly out of sync. As such,
        # there are 3 possible situations:
        #
        # 1. A named type exists in IDA, but does not exist in the context.
        # 2. A named type exists in the context, but does not exist in IDA.
        # 3. A named type exists in both IDA and the context.
        #
        # For case 1:
        # - Process the tinfo taken from IDA, to generate a WilType
        #   - Because the type context is out of sync with IDA, named
        #     references in the WilType might refer to types that are
        #     currently not part of the context. Thus, all named references
        #     are maintained as forward references and not resolved.
        # - Add the tinfo to the type context
        #   - We specifically tell the type context not to sync this type with
        #     IDA for the time being.
        #   - This means that the tinfo associated with the name in IDA might
        #     not be identical to the tinfo that would be generated from the
        #     WilType. We will need to generate the tinfos later.
        # - Once all types are added, the context will then generate the
        #   tinfos, which will also result in the resolution of all named
        #   references.
        #
        # For case 2:
        # - The context will generate a tinfo to update the IDA type.
        #
        # For case 3:
        # - The context will generate a tinfo to update the IDA type; the type
        #   stored in the context takes precedence over the one in the IDA
        #   local type library.
        #
        # Our strategy will thus be the following:
        # - For each tinfo in IDA's type library:
        #   - If a type with the same name exists in the context:
        #     - Skip.
        #   - Else:
        #     - Generate a WilType from the tinfo
        #       - Use forward refs.
        #     - Add WilType to context, without updating IDA
        # - At this point, all new type information within IDA has been added
        #   to the context.
        # - All names referenced by WilTypes also exist both in the context
        #   and in IDA, so references can be resolved.
        # - We can then get all TypeNames to update IDA.
        #

        DINFO("Syncing type context with IDA:")
        
        maxord = idaapi.get_ordinal_qty(idaapi.cvar.idati)

        for i in range(1, maxord):

            tinfo = idaapi.tinfo_t()
            found = tinfo.get_numbered_type(idaapi.cvar.idati, i)
            if not found: continue

            tyname = tinfo.get_type_name()
            DINFO("\tProcessing type {}.".format(tyname))

            # Skip if a type of this name already exists in the context.
            if tyname in self:
                DINFO("\t\tAlready in context, skipping.")
                continue
            #endif

            # Convert into a WilType.
            try:
                ty = WilType.from_tinfo(tinfo,
                                        ignore_toplevel_ref=True,
                                        use_forward_refs=True,
                                        do_not_resolve=True)
                DBG("\t\tGot type: {!r}".format(ty))

                self.add(tyname, ty, touched=False, _do_not_create_idaname=True)
                DBG("\t\tAdded.")
                if isinstance(ty, ExtendedType):
                    DBG("\t\tMarking as persistent.")
                    ty._mark_as_persistent(i, tyname)
                #endif
                
            except TInfoConversionExn:
                DINFO("\t\tCould not convert to WilType, skipping.")
                continue
            #endtry

        #endfor

        DINFO("\tGoing to update all types now.")
        self.update_all_types()
        
    #enddef
    
#endclass

###############################################
# MODULE INIT
###############################################

async def _module_init(mod):
    DINFO("Initializing type system.")
    await module.current().wait_until_ready()
    Sizes.ADDR = module.current().info["addr_size"]
    return   
#enddef

#
# UNIT TESTS
#

import unittest

class Test(event.EventTestCase):

    def setUp(self):
        super().setUp()
    #enddef

    @staticmethod
    def simplety(ida_bt_ty):
        tinfo = idaapi.tinfo_t()
        tinfo.create_simple_type(ida_bt_ty)
        return tinfo
    #enddef
    

    def test_primitives(self):
            
        self.assertRaises(NoSizeExn, lambda *args, **kwargs: Unit.bytesize)
        self.assertFalse(Unit.is_signed())
        
        self.assertEqual(1, Int8.bytesize)
        self.assertTrue(Int8.is_signed())
        self.assertEqual(2, Int16.bytesize)
        self.assertTrue(Int16.is_signed())
        self.assertEqual(4, Int32.bytesize)
        self.assertTrue(Int32.is_signed())
        self.assertEqual(8, Int64.bytesize)
        self.assertTrue(Int64.is_signed())
        self.assertEqual(16, Int128.bytesize)
        self.assertTrue(Int128.is_signed())

        self.assertEqual(1, UInt8.bytesize)
        self.assertFalse(UInt8.is_signed())
        self.assertEqual(2, UInt16.bytesize)
        self.assertFalse(UInt16.is_signed())
        self.assertEqual(4, UInt32.bytesize)
        self.assertFalse(UInt32.is_signed())
        self.assertEqual(8, UInt64.bytesize)
        self.assertFalse(UInt64.is_signed())
        self.assertEqual(16, UInt128.bytesize)
        self.assertFalse(UInt128.is_signed())

        self.assertEqual(1, Bool.bytesize)
        
        self.assertEqual(4, Float.bytesize)
        self.assertTrue(Float.is_signed())
        self.assertEqual(8, Double.bytesize)
        self.assertTrue(Double.is_signed())
        self.assertEqual(16, LDouble.bytesize)
        self.assertTrue(LDouble.is_signed())

        self.assertEqual(self.simplety(idaapi.BTF_VOID), Unit.to_tinfo())

        self.assertEqual(self.simplety(idaapi.BTF_INT8), Int8.to_tinfo())
        self.assertEqual(self.simplety(idaapi.BTF_INT16), Int16.to_tinfo())
        self.assertEqual(self.simplety(idaapi.BTF_INT32), Int32.to_tinfo())
        self.assertEqual(self.simplety(idaapi.BTF_INT64), Int64.to_tinfo())
        self.assertEqual(self.simplety(idaapi.BTF_INT128), Int128.to_tinfo())
        
        self.assertEqual(self.simplety(idaapi.BTF_UINT8), UInt8.to_tinfo())
        self.assertEqual(self.simplety(idaapi.BTF_UINT16), UInt16.to_tinfo())
        self.assertEqual(self.simplety(idaapi.BTF_UINT32), UInt32.to_tinfo())
        self.assertEqual(self.simplety(idaapi.BTF_UINT64), UInt64.to_tinfo())
        self.assertEqual(self.simplety(idaapi.BTF_UINT128), UInt128.to_tinfo())

        # Just a few equality tests should be sufficient.
        self.assertEqual(Int8, Int8)
        self.assertEqual(Int16, Int16)
        self.assertEqual(Int32, Int32)

        # XXX: Add tests for c_printer, if we are still going to use it.
        
    #enddef

#endclass
