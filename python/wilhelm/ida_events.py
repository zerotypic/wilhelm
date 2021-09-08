#
# ida_events : Standard IDA events
#

import contextlib

import idaapi

from . import util
from . import event
from .util import asyncutils

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = util.setup_logger(__name__)

__all__ = []

class IDAEvent(event.Event): pass

class RenameEvent(IDAEvent):
    '''Triggered after an IDA object is renamed.
    This is also triggered when an address is given a name for the first time.
    In such a situation, old_name is set to the empty string.
    This is also triggered when the name of an address is fully deleted. For example, 
    when the name of a location is removed because it becomes part of a function. In
    such a situation, new_name is set to the empty string.
    '''

    def __init__(self, addr, old_name, new_name, **kwargs):
        super().__init__(**kwargs)
        self.addr = addr
        self.old_name = old_name
        self.new_name = new_name
    #enddef
#endclass

class HexRaysLocalRenameEvent(IDAEvent):
    def __init__(self, addr, lvar, new_name, is_user_name, **kwargs):
        super().__init__(**kwargs)
        self.addr = addr
        self.lvar = lvar
        self.new_name = new_name
        self.is_user_name = is_user_name
    #enddef
#endclass

def suppressable(func):
    def _wrap(self, *args, **kwargs):
        if self._ctx.suppress_events: return 0
        return func(self, *args, **kwargs)
    #enddef
    return _wrap
#enddef

# Context object used by hooks.
class _Context(object):
    def __init__(self):
        self.suppress_events = False
        # XXX: This might need to be cleaned out from time to time, see
        # what's a good way to maintain it.
        self.rename_addr_map = {}
    #enddef
#endclass


class IDPHooks(idaapi.IDP_Hooks):

    def __init__(self, ctx):
        super().__init__()
        self._ctx = ctx
    #enddef

    @suppressable
    def ev_rename(self, ea, new_name):
        # Note that this function is called before IDA checks for name
        # conflicts, which means it is possible that a conflict happens
        # and no corresponding renamed() event is triggered.
        # Save old name into rename map.
        self._ctx.rename_addr_map[ea] = idaapi.get_name(ea)
        DBG("ev_rename: 0x%08x, %r -> %r", ea, self._ctx.rename_addr_map[ea], new_name)
        return super().ev_rename(ea, new_name)
    #enddef

    def ev_replaying_undo(self, *args):
        # XXX: How to handle undo events?
        DBG("ev_replaying_undo: args = %r", args)
        return super().ev_replaying_undo(*args)
    #enddef
    
#endclass

class IDBHooks(idaapi.IDB_Hooks):

    def __init__(self, ctx):
        super().__init__()
        self._ctx = ctx
    #enddef

    @suppressable
    def renamed(self, ea, new_name, is_local):
        DBG("IDA renamed event:")
        if not idaapi.is_mapped(ea):
            # This should be a renamed event caused by an enum rename,
            # ignore.
            # Note: Should not longer be triggered in IDA 7.6 onwards.
            DBG("\tTriggered by enum rename, ignoring.")
            return
        #endif
        cur_name = idaapi.get_name(ea)
        DBG("\tCurrent name: %r", cur_name)
        if not ea in self._ctx.rename_addr_map:
            DWARN("renamed: No entry for address 0x%08x found in rename map!", ea)
            return
        #endif
        if is_local:
            if cur_name != "":
                DBG("\tis_local flag is true, but current name is set, ignoring.")
            else:
                # If the name being set is local, it will no longer appear in
                # the list of names. So we should treat this as if it was
                # deleting the old name.
                DBG("\tnew local name %r, treating as name deletion.", new_name)
                new_name = ""
            #endif
        #endif
        old_name = self._ctx.rename_addr_map.pop(ea)
        DBG("\taddr 0x%08x has been renamed: %r -> %r", ea, old_name, new_name)
        ev = RenameEvent(ea, old_name, new_name)
        event.manager.trigger(ev)
    #enddef

    @suppressable
    def local_types_changed(self, *args): pass

    '''
    struc_created
    deleting_struc
    struc_deleted
    changing_struc_align
    struc_align_changed
    renaming_struc
    struc_renamed
    expanding_struc
    struc_expanded
    struc_member_created
    deleting_struc_member
    struc_member_deleted
    renaming_struc_member
    struc_member_renamed
    changing_struc_member
    struc_member_changed
    changing_struc_cmt
    struc_cmt_changed
    XXX CONTINUE FROM HERE

    func_added,             ///< The kernel has added a function.
                            ///< \param pfn  (::func_t *)

    func_updated,           ///< The kernel has updated a function.
                            ///< \param pfn  (::func_t *)

    set_func_start,         ///< Function chunk start address will be changed.
                            ///< \param pfn        (::func_t *)
                            ///< \param new_start  (::ea_t)

    set_func_end,           ///< Function chunk end address will be changed.
                            ///< \param pfn      (::func_t *)
                            ///< \param new_end  (::ea_t)

    deleting_func,          ///< The kernel is about to delete a function.
                            ///< \param pfn  (::func_t *)
                            //
    frame_deleted,          ///< The kernel has deleted a function frame.
                            ///< \param pfn  (::func_t *)

    thunk_func_created,     ///< A thunk bit has been set for a function.
                            ///< \param pfn  (::func_t *)

    func_tail_appended,     ///< A function tail chunk has been appended.
                            ///< \param pfn   (::func_t *)
                            ///< \param tail  (::func_t *)

    deleting_func_tail,     ///< A function tail chunk is to be removed.
                            ///< \param pfn   (::func_t *)
                            ///< \param tail  (const ::range_t *)

    func_tail_deleted,      ///< A function tail chunk has been removed.
                            ///< \param pfn      (::func_t *)
                            ///< \param tail_ea  (::ea_t)

    tail_owner_changed,     ///< A tail chunk owner has been changed.
                            ///< \param tail        (::func_t *)
                            ///< \param owner_func  (::ea_t)
                            ///< \param old_owner   (::ea_t)

    func_noret_changed,     ///< #FUNC_NORET bit has been changed.
                            ///< \param pfn  (::func_t *)

    stkpnts_changed,        ///< Stack change points have been modified.
                            ///< \param pfn  (::func_t *)

    make_code,              ///< An instruction is being created.
                            ///< \param insn    (const ::insn_t*)

    make_data,              ///< A data item is being created.
                            ///< \param ea     (::ea_t)
                            ///< \param flags  (::flags_t)
                            ///< \param tid    (::tid_t)
                            ///< \param len    (::asize_t)

    destroyed_items,        ///< Instructions/data have been destroyed in [ea1,ea2).
                            ///< \param ea1                 (::ea_t)
                            ///< \param ea2                 (::ea_t)
                            ///< \param will_disable_range  (bool)

    byte_patched,           ///< A byte has been patched.
                            ///< \param ea         (::ea_t)
                            ///< \param old_value  (::uint32)

    callee_addr_changed,    ///< Callee address has been updated by the user.
                            ///< \param ea        (::ea_t)
                            ///< \param callee    (::ea_t)

    func_deleted,           ///< A function has been deleted.
                            ///< \param func_ea (::ea_t)

    '''
    
#endclass

class HexRaysHooks(idaapi.Hexrays_Hooks):

    def __init__(self, ctx):
        super().__init__()
        self._ctx = ctx
    #enddef

    def lvar_name_changed(self, vu, v, name, is_user_name):
        addr = vu.cfunc.entry_ea
        ev = HexRaysLocalRenameEvent(addr, v, name, is_user_name)
        event.manager.trigger(ev)
        return super().lvar_name_changed(vu, v, name, is_user_name)
    #enddef

    # def lvar_type_changed(self, vu, v, tinfo) -> int
    #def lvar_cmt_changed(self, vu, v, cmt) -> int

    # def lvar_mapping_changed(self, vu, frm, to):
    #     pass
    # #enddef

    # XXX TODO
    # flowchart(self, fc) -> int
    # stkpnts(self, mba, _sps) -> int
    # prolog(self, mba, fc, reachable_blocks, decomp_flags) -> int
    # microcode(self, mba) -> int
    # preoptimized(self, mba) -> int
    # locopt(self, mba) -> int
    # prealloc(self, mba) -> int
    # glbopt(self, mba) -> int
    # structural(self, ct) -> int
    # maturity(self, cfunc, new_maturity) -> int
    # interr(self, errcode) -> int
    # combine(self, blk, insn) -> int
    # print_func(self, cfunc, vp) -> int
    # func_printed(self, cfunc) -> int
    # resolve_stkaddrs(self, mba) -> int
    # build_callinfo(self, blk, type, callinfo) -> int
    # open_pseudocode(self, vu) -> int
    # switch_pseudocode(self, vu) -> int
    # refresh_pseudocode(self, vu) -> int
    # close_pseudocode(self, vu) -> int
    # keyboard(self, vu, key_code, shift_state) -> int
    # right_click(self, vu) -> int
    # double_click(self, vu, shift_state) -> int
    # curpos(self, vu) -> int
    # create_hint(self, vu) -> PyObject *
    # text_ready(self, vu) -> int
    # populating_popup(self, widget, popup_handle, vu) -> int
    # lvar_name_changed(self, vu, v, name, is_user_name) -> int
    # lvar_type_changed(self, vu, v, tinfo) -> int
    # lvar_cmt_changed(self, vu, v, cmt) -> int
    # lvar_mapping_changed(self, vu, frm, to) -> int
    # cmt_changed(self, cfunc, loc, cmt) -> int

    

#endclass


_ctx = _Context()

idphook = IDPHooks(_ctx)
idphook.hook()

idbhook = IDBHooks(_ctx)
idbhook.hook()

hrhook = HexRaysHooks(_ctx)
hrhook.hook()

@contextlib.contextmanager
def suppress_events():
    DBG("Suppressing IDA events.")
    _ctx.suppress_events = True
    try:
        yield None
    finally:
        DBG("Stop suppressing IDA events.")
        _ctx.suppress_events = False
    #endtry
#enddef

import atexit
@atexit.register
def cleanup():
    print("Cleanup called.")
    idphook.unhook()
    idbhook.unhook()
    hrhook.unhook()
#enddef
