#
# ida_events : Standard IDA events
#

import contextlib

import idaapi

from . import util
from . import event
from .util import asyncutils

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = util.setup_logger(__name__)

# XXX: Change to using this as the base event class
#class IDAEvent(event.Event): pass

class RenameEvent(event.Event):
    class CannotRenameExn(event.EventHandlerExn):
        def __init__(self, reason): self.reason = reason
    #endclass

    def __init__(self, addr, oldname, newname, **kwargs):
        super().__init__(**kwargs)
        self.addr = addr
        self.oldname = oldname
        self.newname = newname
    #enddef
#endclass

def suppressable(func):
    def _wrap(self, *args, **kwargs):
        if self._suppress_events: return 0
        return func(self, *args, **kwargs)
    #enddef
    return _wrap
#enddef


class IDPHooks(idaapi.IDP_Hooks):

    def __init__(self):
        super().__init__()
        self._suppress_events = False
    #enddef

    @suppressable
    def ev_rename(self, ea, new_name):
        # XXX: This function gets called before IDA checks for name
        # conflicts. As a result, event handlers will see a RenameEvent
        # even when IDA will eventually pop up a dialog refusing to
        # perform the rename operation. To be really safe, the
        # idaapi.IDB_Hooks.renamed() callback should be used instead;
        # however this callback only happens after the renaming has taken
        # place, and the old name is lost.
        # For code relying on RenameEvent, it should check to see if there
        # is a name conflict and ignore the event if so.
        ev = RenameEvent(ea, idaapi.get_name(ea), new_name)
        event.manager.trigger(ev)
        DBG("ev_rename: Waiting for event to complete...")
        asyncutils.run_task_till_done(ev.wait_till_handled())
        if ev.has_exceptions():
            DBG("ev:rename: handlers raised exceptions.")
            for (_, exn) in ev.get_exceptions():
                if isinstance(exn, RenameEvent.CannotRenameExn):
                    # XXX: Pop up a dialog box to explain why renaming
                    # failed.
                    DBG("Could not rename: {}".format(exn.reason))
                    return -1
                else:
                    raise exn
                #endif
            #endfor
        #endif        
        DBG("ev_rename: event completed: is_handled={}".format(ev.is_handled()))
        return 0
    #enddef
    
#endclass

class IDBHooks(idaapi.IDB_Hooks):

    def __init__(self):
        super().__init__()
        self._suppress_events = False
    #enddef
    
    def renamed(self, ea, new_name, local_name):
        pass
    #enddef

#endclass

idphook = IDPHooks()
idphook.hook()

idbhook = IDBHooks()
idbhook.hook()

@contextlib.contextmanager
def suppress_events():
    idphook._suppress_events = True
    idbhook._suppress_events = True
    try:
        yield None
    finally:
        idphook._suppress_events = False
        idbhook._suppress_events = False
    #endtry
#enddef

import atexit
@atexit.register
def cleanup():
    print("Cleanup called.")
    idphook.unhook()
    idbhook.unhook()
#enddef
