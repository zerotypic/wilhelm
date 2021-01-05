#
# module : Representation of an IDA database
#

import sys

import idaapi
import idautils

from . import qname
from . import event
from . import ida_events
from . import ast
from . import util
from .util import asyncutils

__all__ = ("Module",)

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = util.setup_logger(__name__)

class Exn(Exception): pass
class ExistingNameExn(Exn): pass
class OverloadMapExn(Exn): pass

# An item is an object that can be found inside a module.
class Item(object):
    def __init__(self, addr):
        self._addr = addr
    #enddef

    @property
    def addr(self): return self._addr

    @classmethod
    def build_item_from_addr(cls, addr):

        flags = idaapi.get_full_flags(addr)

        if idaapi.is_func(flags):
            return FunctionItem(addr)
        else:
            return Item(addr)
        #endif

    #enddef
    
#endclass

class FunctionItem(Item):
    def __init__(self, addr):
        super().__init__(addr)
        self._func = None
    #enddef

    def is_weak(self): return self._func == None
    
    @property
    def func(self):
        if self.is_weak():
            self._func = ast.Function(self.addr)
        #endif
        return self._func
    #enddef
    
#endclass

# XXX: Currently, there can only be one module per IDA instance. This
# class uses API calls that access that module's state,
# e.g. idaapi.get_name(). If we add support for multiple modules, then the
# code here needs to be rewritten.
class Module(object):

    def __init__(self):
        self._value_ctx = qname.Context("value")
        self._type_ctx = qname.Context("type")
    #enddef

    def init_handlers(self):
        self._value_ctx.root.clear_relay_event_observers()
        self._value_ctx.root.add_relay_event_observer(self._observe_value_events)
        self._type_ctx.root.clear_relay_event_observers()
        self._type_ctx.root.add_relay_event_observer(self._observe_type_events)
    #enddef
    
    @property
    def value_context(self): return self._value_ctx

    @property
    def type_context(self): return self._type_ctx

    def get_qname_for_addr(self, addr):
        return self._get_qname_for_ida_name(idaapi.get_name(addr))
    #enddef

    def _get_qns_for_ida_name(self, name):
        dname = idaapi.demangle_name(name, idaapi.MNG_NODEFINIT)
        if dname == None:
            # This is not a mangled name, so just use the name string itself.
            return name
        else:
            # Append mangled name as a suffix to the demangled name.
            return qname.qns_add_suffix(dname, name)
        #endif
    #enddef
            
    def _get_qname_for_ida_name(self, ida_name, build=False):
        qns = self._get_qns_for_ida_name(ida_name)
        return self.value_context.locate(qns, build=build)
    #enddef
    
    def _populate_values(self):
        self.value_context.root.clear()
        for (addr, ida_name) in idautils.Names():
            qname = self._get_qname_for_ida_name(ida_name, build=True)
            qname.entity = Item.build_item_from_addr(addr)
        #endfor
    #enddef

    def _handle_ida_rename(self, ev):
        # XXX: This handler will be called before IDA checks for name
        # conflicts. Also, other handlers could prevent the renaming
        # operation from succeeding. As such, it isn't guaranteed that
        # renaming will actually take place. We deal with this for now by
        # assuming that only name conflicts will cause renaming to
        # fail. Since we check for name conflicts as well, we should never
        # be in a case where IDA doesn't perform a renaming operation
        # while we do.
        
        DBG("Got rename event: %r", ev)
        DBG("\t%r -> %r", ev.oldname, ev.newname)
        DBG("\tName set at addr 0x%08x: %r", ev.addr, idaapi.get_name(ev.addr))
        
        old_qn = self._get_qname_for_ida_name(ev.oldname)

        DBG("old_qn = %r", old_qn)

        # Get the actual new qname we will be using to insert into the
        # value context.
        new_qns = self._get_qns_for_ida_name(ev.newname)
        
        DBG("new_qns = %r", new_qns)
              
        if self.value_context.contains(new_qns):
            # XXX: Check event system to see what happens when an
            # exception is raised, and whether that allows us to cancel
            # the rename operation.
            raise ida_events.RenameEvent.CannotRenameExn(
                "Name {} already exists.".format(new_qns)
            )
            #raise ExistingNameExn("Name {} already exists.".format(new_qns))
        #endif

        # If the object being renamed is a function, check to see if the
        # new name is local to the function, and if so, refuse to rename.
        if idaapi.is_func(idaapi.get_flags(ev.addr)):
            if idaapi.is_name_defined_locally(idaapi.get_func(ev.addr),
                                              ev.newname,
                                              idaapi.ignore_none):
                raise ida_events.RenameEvent.CannotRenameExn(
                    "Name {} is local to function.".format(new_qns)
                )
            #endif
        #endif
        
        # Perform the actual move.
        DBG("Moving qname from %r to %r.", old_qn.fullname, new_qns)
        self.value_context.move(old_qn.fullname, new_qns)

        DBG("Done.")
        
    #enddef

    def __post_handle_orphan_qname(self, ev):
        with ida_events.suppress_events():
            addr = ev.qname.entity.addr
            DBG("Deleting name at address 0x%08x", addr)
            idaapi.set_name(addr, "")
            # Get the auto-generated name
            auto_name = idaapi.get_name(addr)
        #endwith
        qname = self._get_qname_for_ida_name(auto_name, build=True)
        # XXX: Incomplete, finish this!
        # qname.entity = Item.build_item_from_addr(addr)
    #enddef
    
    def _handle_value_events(self, ev):
        DBG("Handling value context qname event %r.", ev)

        if not isinstance(ev, qname.QNameEvent):
            WARN("Received non-qname event %r, ignoring.", ev)
            return
        #endif
        if ev.ctx != self.value_context:
            WARN("Context of event %r does not match our value context, ignoring", 
                 ev)
            return
        #endif

        if isinstance(ev, qname.RenameEvent):
            DBG("qname %r has been renamed. Syncing IDA to match.", qname)
            with ida_events.suppress_events():
                for qn in ev.qname.terminals():
                    DBG("Setting name of addr 0x%08x to %s",
                        qn.entity.addr, qn.fullname)
                    idaapi.set_name(qn.entity.addr, qn.fullname)
                #endfor
            #endwith
        elif isinstance(ev, qname.OrphanEvent):
            # Register a post-handler
            raise event._PrivilegedHandlerPostActionExn(self.__post_handle_orphan_qname)
        #endif
       
    #enddef

    def _handle_type_events(self, ev):
        pass
    #enddef

    
#endclass

_CURRENT_MODULE = None
def current(): return _CURRENT_MODULE

def init_current_module():
    mod = Module()
    sys.modules[__name__]._CURRENT_MODULE = mod
    mod._populate_values()
    asyncutils.run_task_till_done(event.manager.wait_till_queue_empty())
    event.manager._register_handler(ida_events.RenameEvent, mod._handle_ida_rename, priority=-99)
    event.manager._register_handler(
        qname.QNameEvent,
        mod._handle_value_events,
        tag=mod.value_context.name,
        priority=-99)
    event.manager._register_handler(
        qname.QNameEvent,
        mod._handle_type_events,
        tag=mod.type_context.name,
        priority=-99)

    def foo(loop, context):
        print("Handling exception in loop {!r}".format(loop))
        print("context = {!r}".format(context))
        _CURRENT_MODULE.foo_exn_info = (loop, context)
    #enddef
    import asyncio
    asyncio.get_event_loop().set_exception_handler(foo)
    
#enddef


#
# UNIT TESTS
#

import unittest

class Test(unittest.TestCase):

    def test_module(self):

        mod = Module()

        self.assertEqual(type(mod.value_context), qname.Context)
        self.assertEqual(type(mod.type_context), qname.Context)
        
    #enddef

#endclass
