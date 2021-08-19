#
# module : Representation of an IDA database
#

import sys
import asyncio

import idaapi
import idautils

from . import qname
from . import event
from . import ida_events
from . import ast
from . import util
from .util import asyncutils

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = util.setup_logger(__name__)

__all__ = ("Module", "current")

# Gets called on startup when module feature is enabled.
async def _module_init(mod):
    await mod.init_current_module()
#enddef

class Exn(Exception): pass
class ExistingNameExn(Exn): pass
class NotTerminalExn(Exn): pass
class HasSuffixesExn(Exn): pass

# An item is an object that can be found inside a module.
# Items are designed to be lazy by default, holding only their address. To
# access other values associated with an item, the item must be "called"
# first: item().some_value
class Item(object):
    def __init__(self, addr):
        self._addr = addr
        self._is_lazy = True
    #enddef

    @property
    def addr(self): return self._addr

    @property
    def is_lazy(self): return self._is_lazy
    
    def realize(self): pass
    
    def __call__(self):
        if self._is_lazy:
            self.realize()
            self._is_lazy = False
        #endif
        return self
    #enddef
    
    @classmethod
    def build_item_from_addr(cls, addr):

        flags = idaapi.get_full_flags(addr)

        if idaapi.is_func(flags):
            return FunctionItem(addr)
        elif idaapi.is_data(flags):
            return DataItem(addr)
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

    def realize(self):
        self._func = ast.Function(self.addr)
    #enddef

    @property
    def func(self):
        if self._func == None: self()
        return self._func
    #enddef
    
#endclass

# XXX: Add more specialized subclasses for different kinds of
# data types. 
class DataItem(Item):
    def __init__(self, addr):
        super().__init__(addr)
        self._size = idaapi.get_item_size(addr)
        self._data = idaapi.get_bytes(addr, self._size)
    #enddef
    @property
    def size(self): return self._size
    @property
    def data(self): return self._data
#endclass    

class ValueContext(qname.Context):

    def __init__(self, mod, name="values"):
        super().__init__(name)
        self._parent_module = mod
    #enddef

    def get(self, qns):
        '''Retrieves an item from the value context. QName should be that of a
        terminal; otherwise an exception is raised.
        '''

        try:
            qn = self.locate(qns)
        except qname.NotFoundExn as e:
            if qname.qns_suffix(qns) == None:
                # Check to see if suffixes exist for this qname.
                names = self.locate(qns, gather_suffixes=True)
                if len(names) == 1:
                    qn = names[0]
                elif len(names) > 1:
                    raise HasSuffixesExn("{} has multiple suffixes.".format(qns))
                else:
                    raise e
                #endif
            #endif
        #endtry
            
        if qn.is_terminal:
            return qn.entity
        else:
            raise NotTerminalExn("{} is not a terminal value.".format(qns))
        #endif
    #enddef

    def get_suffixes(self, qns):
        '''Retrieves all suffixes of the provided QName.

        If the QName is that of an unsuffixed terminal, it is returned as
        well. Any suffixes in the provided QName are ignored; only the
        unsuffixed basename is used.
        '''
        return [(qn, qn.entity) for qn in self.locate(qns, gather_suffixes=True)]
    #enddef
    
    def get_qname(self, qns):
        '''Returns a QName object from the value context.'''
        return self.locate(qns)
    #enddef            
    
    def add(self, qns, addr, caused_by=None):
        '''Add a new item to the value context.

        The item is constructed based on the provided address, and added to
        the value context using the provided QName.

        :qns: QName of the item, provided as a string.
        :addr: Address of the item that is to be added.
        '''
        qn = self.locate(qns, build=True, caused_by=caused_by)
        if qn.entity == None:
            qn.entity = Item.build_item_from_addr(addr)
        else:
            # XXX: Should raise an exception
            pass
        #endif
        return qn
    #enddef

    def __getitem__(self, key):
        try:
            return self.get(key)
        except (qname.NotFoundExn, NotTerminalExn):
            raise KeyError(key)
        #endtry
    #enddef
    def __iter__(self):
        return (it.entity for it in super().__iter__())
    #enddef
    
#endclass


class ModuleEvent(event.Event): pass
class ModuleReadyEvent(ModuleEvent): pass

# XXX: Currently, there can only be one module per IDA instance. This
# class uses API calls that access that module's state,
# e.g. idaapi.get_name(). If we add support for multiple modules, then the
# code here needs to be rewritten.
class Module(event.Emitter):

    def __init__(self):
        super().__init__()
        self._value_ctx = ValueContext(self)
        self._type_ctx = qname.Context("type")
        self._ready_event = asyncio.Event()
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
    def values(self): return self._value_ctx
    
    @property
    def type_context(self): return self._type_ctx

    @property
    def types(self): return self._type_ctx

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
        return self.value_context.locate(qns, build=build, caused_by=self)
    #enddef

    def _create_qname_and_entity(self, ida_name, addr):
        DBG("_create_qname_and_entity: 0x%08x, %r", addr, ida_name)
        qn = self._get_qname_for_ida_name(ida_name, build=True)
        DBG("\tqn = %r", qn)
        # If the qname already exists, the entity might be set. Don't
        # overwrite it.
        if qn.entity == None:
            qn.entity = Item.build_item_from_addr(addr)
        #endif
        return qn
    #enddef
    
    async def _populate_values(self):
        await self.value_context.root.clear_async()
        for (addr, ida_name) in util.get_all_names():
            self._create_qname_and_entity(ida_name, addr)
            await asyncio.sleep(0)
        #endfor
    #enddef

    async def _set_ready(self):
        self._ready_event.set()
        await self.emit_event_async(ModuleReadyEvent)
    #enddef
    def is_ready(self): return self._ready_event.is_set()
    async def wait_until_ready(self): await self._ready_event.wait()
    
    async def _handle_ida_rename(self, ev):

        DBG("Got rename event: %r", ev)
        DBG("\t0x%08x: %r -> %r", ev.addr, ev.old_name, ev.new_name)
        DBG("\tCurrent IDA name: %r", idaapi.get_name(ev.addr))

        if ev.old_name == ev.new_name:
            DBG("\tNames match, ignoring.")
            return
        #endif
        
        if ev.old_name == "":
            # This is an address that had no preivous name. Create a new
            # qname object for it.
            DBG("\tNew name added to database: %r", ev.new_name)
            self._create_qname_and_entity(ev.new_name, ev.addr)
            return
        #endif
        
        old_qn = self._get_qname_for_ida_name(ev.old_name)

        DBG("\told_qn = %r", old_qn)

        if ev.new_name == "":
            DBG("\tName was deleted from database: %r", ev.old_name)

            if ev.old_name == idaapi.get_name(ev.addr):
                # This is the case where the name being deleted is the
                # same as the currently assigned dummy address, which
                # means effectively there was no change. Ignore.
                DBG("\tName being deleted is the dummy address, ignoring.")
                return
            #endif

            await old_qn.parent.remove_child_async(old_qn.basename, caused_by=self)
            return
        #endif
        
        # Get the actual new qname we will be using to insert into the
        # value context.
        new_qns = self._get_qns_for_ida_name(ev.new_name)
        
        DBG("\tnew_qns = %r", new_qns)
              
        if self.value_context.contains(new_qns):
            # This shouldn't happen, as IDA shouldn't allow two addresses
            # to have the same name.
            # Nevertheless, to handle this situation, we re-rename the
            # address to include a suffix, which should keep the name
            # unique.
            DWARN("\tIDA-renamed name for 0x%08x already exists, trying to fix.", ev.addr)
            DWARN("\told name = %r", ev.old_name)
            DWARN("\tnew name = %r", new_qns)
            if qname.qns_suffix(new_qns) != None:
                DERROR("Name clash at 0x%08x, already suffixed: %r", ev.addr, new_qns)
                raise ExistingNameExn("Name {} already exists and has suffix".format(new_qns))
            #endif
            new_qns = qname.qns_add_suffix(new_qns, hex(ev.addr)[2:])
            if self.value_context.contains(new_qns):
                DERROR("Name clash at 0x%08x, including suffix: %r", ev.addr, new_qns)
                raise ExistingNameExn("Name {} already exists after adding suffix".format(new_qns))
            #endif
            DWARN("\tadded suffix to name: %r", new_qns)
            with ida_events.suppress_events():
                idaapi.set_name(ev.addr, new_qns)
            #endwith
        #endif
       
        # Perform the actual move.
        DBG("\tMoving qname from %r to %r.", old_qn.fullname, new_qns)
        self.value_context.move(old_qn.fullname, new_qns, caused_by=self)

        DBG("\tDone.")
        
    #enddef

    def __post_handle_orphan_qname(self, ev):
        with ida_events.suppress_events():
            addr = ev.qname.entity.addr
            DBG("Deleting name at address 0x%08x", addr)
            idaapi.set_name(addr, "")
            # Get the dummy name
            dummy_name = idaapi.get_name(addr)
        #endwith
        # For some addresses, a dummy name will be created if the
        # user-defined name is deleted.
        DBG("\tdummy name = %r", dummy_name)
        if dummy_name != "":
            # When this code runs, the context is in a dirty state as it
            # is halfway through deleting this name. Wait till it is clean
            # before creating the new dummy name.
            DBG("\tWaiting for context to be clean before creating new qname.")
            async def _create_qname_with_dummy_name():
                await self.value_context.wait_until_clean()
                DBG("\tCreating new qname using dummy name.")
                self._create_qname_and_entity(dummy_name, addr)
            #enddef
            asyncutils.spawn_task(_create_qname_with_dummy_name())
        #endif
    #enddef
    
    def _handle_value_events(self, ev):
        DBG("Handling value context qname event %r.", ev)

        if not isinstance(ev, qname.QNameEvent):
            DWARN("Received non-qname event %r, ignoring.", ev)
            return
        #endif
        if ev.ctx != self.value_context:
            DWARN("Context of event %r does not match our value context, ignoring", 
                 ev)
            return
        #endif

        if ev.caused_by() == self:
            DBG("Event %r originated from this module, ignoring.", ev)
            return
        #endif
        
        if isinstance(ev, qname.RenameEvent) or isinstance(ev, qname.ChildMoveEvent):
            DBG("Received RenameEvent/ChildMoveEvent for qname %r, syncing IDA to match.", ev.qname)
        
            with ida_events.suppress_events():
                for qn in ev.qname.terminals():
                    if idaapi.get_name(qn.entity.addr) != qn.fullname:
                        DBG("Setting name of addr 0x%08x from %r to %r",
                            qn.entity.addr, idaapi.get_name(qn.entity.addr), qn.fullname)
                        idaapi.set_name(qn.entity.addr, qn.fullname)
                    #endif
                #endfor
            #endwith
            
        elif isinstance(ev, qname.OrphanEvent):
            # Register a post-handler
            raise event._PrivilegedHandlerPostActionExn(self.__post_handle_orphan_qname)

        elif isinstance(ev, qname.AddChildEvent):
            # XXX: Implement this?
            pass
            
        #endif
        
    #enddef

    def _handle_type_events(self, ev):
        pass
    #enddef

    
#endclass

_CURRENT_MODULE = None
def current(): return _CURRENT_MODULE

async def init_current_module():
    mod = Module()
    sys.modules[__name__]._CURRENT_MODULE = mod
    DINFO("Populating values....")
    event.manager._set_global_disable(True)
    await mod._populate_values()
    event.manager._set_global_disable(False)
    DINFO("Done.")
    # await event.manager.wait_till_queue_empty()
    DINFO("Ready to register event handlers, registering...")
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
    DINFO("Done.")
    await mod._set_ready()
    return mod
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
