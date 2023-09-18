#
# typeditor : UI for editing types
#

import enum
import idaapi
import asyncio

from . import module
from . import event
from . import qname
from . import types as T
from . import type_disp
from . import util
from .util import TYPECHECK, TypecheckExn
from .util import tokenizedviewer
from .util.disptokens import Token

class Exn(Exception): pass
class UnimplementedExn(Exn): pass
class UnsupportedTypeExn(Exn): pass

__all__ = ("TypeEditor")

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = util.setup_logger(__name__)

ActionCode = enum.Enum("ActionCode", (
    # Per-type actions
    "UNKNOWN",
    "NAVIGATE",
    "RENAME",
    "RESIZE",
    "CHANGE_TYPE",
    "CHANGE_OFFSET",
    "INSERT",
    "INSERT_DEFAULT",
    "DELETE",
    "SHIFT_UP",
    "SHIFT_DOWN",
    "REMOVE_TYPE",

    # Global actions
    "ADD_TYPE",
    "POP_HISTORY",
))

# Abstract base class of all type views
class TypeView(tokenizedviewer.View):

    def __init__(self, ty_qname : qname.QName, viewer : tokenizedviewer.TokenizedViewer):
        super().__init__(ty_qname.fullname,  viewer)
        self.ty_qname = ty_qname
    #enddef

    @property
    def ty(self) -> T.WilType : return self.ty_qname.entity

    def get_prefix_lines(self): raise UnimplementedExn("Must be implemented by subclass.")

    def get_start_offset(self): return len(self.get_prefix_lines())
    
    def to_disptokens(self):
        prefix_tokens = tuple(Token.add_seps((Token.DISP(l) for l in self.get_prefix_lines())))
        return prefix_tokens + type_disp.to_disptokens(self.ty_qname.fullname, self.ty)
    #enddef

    def find_navigable_ty_qname_in_token(self, token):
        raise UnimplementedExn("Must be implemented by subclass.")
    #enddef
    
    def do_user_navigate(self, token):
        DBG("do_user_navigate: token is {!r}".format(token))
        ty_qname = self.find_navigable_ty_in_token(token)
        if ty_qname != None:
            DBG("\tFound navigable type name {!r}, jumping.".format(ty_qname))
            self._viewer.jump_to_ty(ty_qname.fullname)
            DBG("\tAdding self to history.")
            self._viewer.push_history(self)
        #endif
    #enddef
    
    def do_user_rm_ty(self):
        DINFO("TypeView.do_user_rm_ty:")
        confirm = idaapi.ask_yn(
            idaapi.ASKBTN_NO,
            "Are you sure you want to delete type {}?".format(self.ty_qname.fullname)
        )

        if confirm == idaapi.ASKBTN_YES:
            DINFO("\tRemoving type {} ({!r})".format(self.ty_qname.fullname, self.ty))
            self.ty_qname.parent.remove_child(self.ty_qname.basename)
            DINFO("\tRemoved.")
        else:
            DINFO("\tCancelled by user.")
        #endif
        
    #enddef
    
    def handle_action(self, action_code : ActionCode, token):
        DBG("TypeView.handle_action: {!r}".format(action_code))
        match (action_code, token):
            case (ActionCode.NAVIGATE, token):
                # XXX: Special case here where we extract the word under the
                # cursor (which might be part of a token, and not the entire
                # token), and use that word for navigation.
                # XXX: TODO
                self.do_user_navigate(token)
            case (ActionCode.SHIFT_UP, _):
                DINFO("Shifting view {} up.".format(self.name))
                self._viewer.shift_view_up(self.name)
                return
            case (ActionCode.SHIFT_DOWN, _):
                DINFO("Shifting view {} down.".format(self.name))
                self._viewer.shift_view_down(self.name)
                return
            case (ActionCode.REMOVE_TYPE, _):
                self.do_user_rm_ty()
                return
            case _:
                DWARN("Unknown action code {!r}".format(action_code))
        #endmatch
    #enddef    

    def update_ty(self, new_ty):
        self.ty_qname.entity = new_ty
    #enddef
    
#endclass

class StructView(TypeView):

    def __init__(self, *args, **kwargs):
        return super().__init__(*args, **kwargs)
    #enddef
    
    def get_prefix_lines(self):
        return (
            idaapi.COLSTR("//", idaapi.SCOLOR_DSTR),
            idaapi.COLSTR("// {}".format(self.ty_qname.fullname), idaapi.SCOLOR_DSTR),
            idaapi.COLSTR("//", idaapi.SCOLOR_DSTR),
        )
    #enddef

    def find_navigable_ty_in_token(self, token):
        DBG("find_navigable_ty_in_token: token = {!r}".format(token))
        def _get_name(ty):
            DBG("\t_get_name, ty = {!r}".format(ty))
            match ty:
                case T.Pointer():
                    return _get_name(ty.target)
                case T.Array():
                    return _get_name(ty.elem_ty)
                case T.NamedRef():
                    DBG("\t_get_name found name: {}".format(ty.tyname.fullname))
                    return ty.tyname
                case _:
                    DBG("\tget_name did not find a type name.")
                    return None
            #endmatch
        #enddef
        match token:
            case type_disp.StructFieldTypeToken(obj=(ty, i)):
                DBG("\tStructFieldTypeToken, ty = {!r}, i = {}".format(ty, i))
                (_, _, field_ty) = ty.fields[i]
                DBG("\tField type = {!r}".format(field_ty))
                return _get_name(field_ty)
            case _:
                DBG("\tNot a navigable token.")
                return None
        #endmatch
    #enddef
    
    def handle_action(self, action_code, token):
        DINFO("StructView.handle_action: {!r}".format((action_code, token)))
        match (action_code, token):
            case (ActionCode.RENAME, type_disp.StructFieldToken(obj=(_, i))):
                return self.rename_field(i)
            case (ActionCode.RESIZE, _):
                return self.resize_ty()
            case (ActionCode.CHANGE_OFFSET, type_disp.StructFieldToken(obj=(_, i))):
                return self.change_field_offset(i)
            case (ActionCode.CHANGE_TYPE, type_disp.StructFieldToken(obj=(_, i))):
                return self.change_field_ty(i)
            case (ActionCode.INSERT, _):
                return self.insert_field()
            case (ActionCode.INSERT_DEFAULT, type_disp.StructFieldToken(obj=(_, i))):
                return self.insert_field(use_defaults=True, reference_field_idx=i)
            case (ActionCode.INSERT_DEFAULT, _):
                return self.insert_field(use_defaults=True)
            case (ActionCode.DELETE, type_disp.StructFieldToken(obj=(_, i))):
                return self.delete_field(i)
            case (ActionCode.RENAME, _):
                # If we hit this rename, it means the cursor is somewhere
                # that's not a field token, so we take it to mean the user
                # wants to rename the type itself.
                return self.rename_ty()
            case _:
                return super().handle_action(action_code, token)
        #endmatch
    #enddef

    def rename_ty(self):
        DINFO("Calling StructView.rename_ty():")
        old_fullname = self.ty_qname.fullname
        new_fullname = idaapi.ask_str(old_fullname, 230, "New type name: ")
        if new_fullname == None:
            DINFO("\tCancelled by user.")
            return
        #endif
        
        self._viewer.move_ty(old_fullname, new_fullname)
        DINFO("\tRenamed type from {} to {}.".format(old_fullname, new_fullname))
        self.ty_qname = module.current().type_context[new_fullname]

    #enddef

    def resize_ty(self):
        DINFO("Calling StructView.resize_ty().")
        old_size = self.ty.total_size
        new_size = idaapi.ask_long(old_size if old_size != None else 0, "New size (set to 0 for auto): ")
        if new_size == None:
            DINFO("\tCancelled by user.")
            return
        #endif
        if new_size < 0:
            DWARN("\tInvalid size {:d}".format(new_size))
            idaapi.warning("Invalid size {:d}. Size must be non-negative.".format(new_size))
            return
        #endif

        if new_size == 0: new_size = None
        try:
            new_ty = self.ty.modify_size(new_size)
            new_ty.validate()
        except T.InvalidSizeExn as e:
            DWARN("\tInvalid size {:d}: {}".format(new_size, e))
            idaapi.warning("Invalid size {:d}: {}".format(new_size, e))
            return
        except T.InvalidFieldsExn as e:
            DWARN("\tInvalid size {:d}, could not generate new type from specification.".format(new_size))
            idaapi.warning("Invalid size {:d}, could not generate new type from specification.".format(new_size))
            return
        #endtry
        
        self.update_ty(new_ty)

    #enddef

    def rename_field(self, field_idx):
        DINFO("Calling StructView.rename_field, idx = {}:".format(field_idx))

        (_, old_name, _) = self.ty.fields[field_idx]
        new_name = idaapi.ask_str(old_name, 231, "New field name: ")
        if new_name == None:
            DINFO("\tCancelled by user.")
            return
        #endif


        DINFO("\tConstructing new type.")
        new_ty = self.ty.modify(field_idx, T.Struct.FIELDSPEC.NAME, new_name)
        try:
            new_ty.validate()
        except T.InvalidFieldsExn as e:
            DWARN("\tInvalid name '{}', could not generate new type from specification.".format(new_name))
            idaapi.warning("Invalid name '{}, could not generate new type from specification.".format(new_name))
            return
        #endtry

        DINFO("\tUpdating type in context.")
        self.update_ty(new_ty)
    #enddef

    def change_field_ty(self, field_idx):
        DINFO("Calling StructView.change_field_ty, idx = {}:".format(field_idx))

        (_, _, old_fieldty) = self.ty.fields[field_idx]
        old_fieldty_dispstr = type_disp.to_dispstr(old_fieldty)

        new_fieldty_dispstr = idaapi.ask_str(old_fieldty_dispstr, 232, "New field type: ")
        if new_fieldty_dispstr == None:
            DINFO("\tCancelled by user.")
            return
        #endif
        try:
            new_fieldty = type_disp.from_dispstr(new_fieldty_dispstr)
        except type_disp.ConversionExn:
            DWARN("\tInvalid type supplied: {}".format(new_fieldty_dispstr))
            idaapi.warning("Supplied type '{}' could not be parsed.".format(new_fieldty_dispstr))
            return
        #endif

        DINFO("\tNew field type: {!r} ({!r})".format(new_fieldty, new_fieldty_dispstr))

        DINFO("\tConstructing new type.")
        new_ty = self.ty.modify(field_idx, T.Struct.FIELDSPEC.TYPE, new_fieldty, preserve_size=False)
        try:
            new_ty.validate()
        except T.InvalidFieldsExn as e:
            DWARN("\tInvalid field type {}, could not generate new type from specification.".format(new_fieldty_dispstr))
            idaapi.warning("Invalid field type {}, could not generate new type from specification.".format(new_fieldty_dispstr))
            return
        #endtry
        
        DINFO("\tUpdating type in context.")
        self.update_ty(new_ty)

    #enddef

    def change_field_offset(self, field_idx):
        DINFO("Calling StructView.change_field_offset, idx = {}:".format(field_idx))

        (old_offset, _, _) = self.ty.fields[field_idx]
        new_offset = idaapi.ask_long(old_offset, "New field offset: ")
        if new_offset == None:
            DINFO("\tCancelled by user.")
            return
        #endif
        if new_offset < -1:
            DWARN("\tInvalid offset supplied: {}".format(new_offset))
            idaapi.warning("Invalid offset {:d}: offsets must either be non-negative, or -1 for automatic offset calculation.".format(new_offset))
            return
        #endif
        
        DINFO("\tConstructing new type.")
        new_ty = self.ty.modify(field_idx, T.Struct.FIELDSPEC.OFFSET, new_offset, preserve_size=False)
        try:
            new_ty.validate()
        except T.InvalidFieldsExn as e:
            DWARN("\tInvalid offset {:d}, could not generate new type from specification.".format(new_offset))
            idaapi.warning("Invalid offset {:d}, could not generate new type from specification.".format(new_offset))
            return
        #endtry
        
        DINFO("\tUpdating type in context.")
        self.update_ty(new_ty)

    #enddef

    def insert_field(self, use_defaults=False, reference_field_idx=-1):
        DINFO("Calling StructView.insert_field:")

        if not use_defaults:
        
            # Build form to ask for field values.
            frm = idaapi.Form('''
            Insert Field
            <Offset :{offset}> <Type :{ty_dispstr}> <Name :{name}>
            ''', {"offset" : idaapi.Form.NumericInput(tp=idaapi.Form.FT_INT64),
                  "ty_dispstr" : idaapi.Form.StringInput(),
                  "name" : idaapi.Form.StringInput()
                  })
            frm.Compile()

            if frm.Execute():
                field_offset = frm.offset.value
                if field_offset < -1:
                    DWARN("\tInvalid offset supplied: {}".format(field_offset))
                    idaapi.warning("Invalid offset {:d}: offsets must either be non-negative, or -1 for automatic offset calculation.".format(field_offset))
                    return
                #endif
                
                field_name = frm.name.value
                # XXX: We probably should validate the name here. IDA appears
                # to let us use anything we want as a field name though,
                # without complaining. Implement this when its clear what the
                # restrictions on struct field names should be.
                
                try:
                    field_ty = type_disp.from_dispstr(frm.ty_dispstr.value)
                except type_disp.ConversionExn:
                    DWARN("\tInvalid type supplied: {}".format(frm.ty_dispstr.value))
                    idaapi.warning("Supplied type '{}' could not be parsed.".format(frm.ty_dispstr.value))
                    return
                #endtry

                if field_offset >= 0 and not self.ty.is_safe_to_add_field_at_offset(field_offset, field_ty):
                    DWARN("\tSupplied offset {:d} is not safe for adding type {!r}".format(field_offset, field_ty))
                    idaapi.warning("Cannot insert field of type {} at offset {:d} as it will overlap existing fields.".format(type_disp.to_dispstr(field_ty), field_offset))
                    return
                #endif
                
            else:
                DINFO("\tCancelled by user.")
                return
            #endif
                
        else:
            DINFO("\tCalculating best offset to insert field.")
            calced_fields = self.ty.get_calced_field_info()

            # Handle special case where calced_fields is empty, i.e. the struct is empty.
            if len(calced_fields) == 0:
                field_offset = 0
            else:
                while True:
                    DBG("\treference_field_idx == {}".format(reference_field_idx))
                    (ref_offset, _, _, ref_ty) = calced_fields[reference_field_idx]
                    field_offset = ref_offset + ref_ty.bytesize
                    DBG("\t\tTrying offset {:x}".format(field_offset))
                    if self.ty.is_safe_to_add_field_at_offset(field_offset, T.UInt32):
                        DBG("\t\tNo field at offset, ok to proceed.")
                        break
                    else:
                        DBG("\t\tField exists at offset, trying another index.")
                        reference_field_idx += 1
                        if reference_field_idx >= len(calced_fields):
                            reference_field_idx = -1
                        #endif
                    #endif
                #endwhile
            #endif
            
            DINFO("\tUsing offset: {}".format(field_offset))

            # Find an unused name for the field name.
            base_field_name = "field_{:03x}".format(field_offset)
            field_name = base_field_name
            i = 1
            while self.ty.has_field_with_name(field_name):
                field_name = "{}_{:d}".format(base_field_name , i)
            #endwhile
            
            field_ty = T.UInt32
            
        #endif

        DINFO("\tInserting field: {!r}".format((field_offset, field_name, field_ty)))

        new_ty = self.ty.extend(((field_offset, field_name, field_ty),))

        try:
            new_ty.validate()
        except T.InvalidFieldsExn as e:
            DWARN("\tInvalid field entry, could not generate new type from specification.")
            idaapi.warning("Invalid field entry, could not generate new type from specification.")
            return
        #endtry
        
        self.update_ty(new_ty)

    #enddef

    def delete_field(self, field_idx):
        DINFO("Calling StructView.delete_field, idx = {}.".format(field_idx))
        new_ty = self.ty.remove_field(field_idx)
        try:
            new_ty.validate()
        except T.InvalidFieldsExn as e:
            DWARN("\tInvalid deletion, could not generate new type from specification.")
            idaapi.warning("Invalid deletion, could not generate new type from specification.")
            return
        #endtry
        
        self.update_ty(new_ty)
    #enddef
    
#enddef

# Key bindings that apply to a specific type.
PERTYPE_KEY_MAP = {
    (13, 0) : ActionCode.NAVIGATE,              # <Enter>
    (78, 0) : ActionCode.RENAME,                # "N"
    (90, 0) : ActionCode.RESIZE,                # "Z"
    (79, 0) : ActionCode.CHANGE_OFFSET,         # "O"
    (89, 0) : ActionCode.CHANGE_TYPE,           # "Y"

    (73, 1) : ActionCode.INSERT,                # <Shift>-"I"
    (73, 0) : ActionCode.INSERT_DEFAULT,        # "I"
    (68, 0) : ActionCode.DELETE,                # "D"

    (219, 0) : ActionCode.SHIFT_UP,             # "["
    (221, 0) : ActionCode.SHIFT_DOWN,           # "]"

    (46, 0) : ActionCode.REMOVE_TYPE,           # <Delete>
}

# Global key bindings.
GLOBAL_KEY_MAP = {
    (45, 0) : ActionCode.ADD_TYPE,              # <Insert>
    (27, 0) : ActionCode.POP_HISTORY,           # <Esc>
}

HOTKEY = "Ctrl-F1"

class TypeEditor(tokenizedviewer.TokenizedViewer):

    # XXX: Need to enforce that there is only 1 TypeEditor object for the module.
    
    def __init__(self, ctx : T.TypeContext, window_title="Type Editor"):
        super().__init__(PERTYPE_KEY_MAP, view_sep="\n")
        self.ctx = ctx
        self._window_title = window_title
        self.register_hotkey()
        self.created = False
    #enddef

    def __del__(self):
        self.unregister_hotkey()
    #enddef
    
    def Create(self):
        super().Create(self._window_title)
        self.register_context_observer()
        self.add_types_from_context()
        self.created = True
    #enddef

    def register_hotkey(self):
        self.hotkey_ctx = idaapi.add_hotkey(HOTKEY, self.on_hotkey)
    #enddef

    def unregister_hotkey(self):
        if hasattr(self, "hotkey_ctx"):
            idaapi.del_hotkey(self.hotkey_ctx)
        #endif
    #enddef

    def on_hotkey(self):
        DINFO("Hotkey pressed.")
        if not self.created: self.Create()
        self.Show()
    #enddef
    
    def setup_view_info(self, vi):
        vi.extra = {}
        return super().setup_view_info(vi)
    #enddef

    def register_context_observer(self):
        self.ctx.root.add_relay_event_observer(self._ctx_root_observer)
    #enddef
    def _ctx_root_observer(self, bearing, ev):
        match ev:
            case qname.AddChildEvent(parent, childname):
                self.add_ty(parent[childname])
            case qname.RemoveChildEvent(parent, childname):
                self.remove_ty(parent[childname])
        #endmatch
    #enddef
    
    def add_types_from_context(self):
        for qn in self.ctx.all_typenames():
            if isinstance(qn.entity, T.Struct):
                self.add_ty(qn, render=False)
            #endif
        #endfor
        self.render()
    #enddef
    
    def add_ty(self, ty_qname : qname.QName, render=True):
        DINFO("Adding type {}".format(ty_qname.fullname))
        match ty_qname.entity:
            case T.Struct():
                view = StructView(ty_qname, self)
            case _:
                raise UnsupportedTypeExn("Cannot add type {} as the {} is unsupported.".format(ty_qname.fullname, ty_qname.entity))
        #endmatch

        self.add_view(view, render=render)

        ty_qname.add_relay_event_observer(self._observe_ty_qname)
        
    #enddef

    def remove_ty(self, ty_qname):
        DINFO("Removing type {}".format(ty_qname.fullname))
        if self.has_view(ty_qname.fullname):
            ty_qname.remove_relay_event_observer(self._observe_ty_qname)
            self.remove_view(ty_qname.fullname)
        #endif
    #enddef
    
    def jump_to_ty(self, ty_qname_str):
        self.jump_to_view(ty_qname_str)
    #enddef

    def _handle_ty_rename(self, qn, old_name, new_name):
        DBG("_handle_ty_rename: {!r}".format((qn, old_name, new_name)))
        # Due to the event system, this function might be called multiple
        # times for a single rename. Check to see if a view with the old name
        # exists first; if it doesn't, it must have already been renamed.
        if self.has_view(old_name):
            view = self.get_view(old_name)
            view.name = new_name
        #endif
    #enddef
    
    def _observe_ty_qname(self, brg, ev):
        DINFO("_observe_ty_qname: {!r}".format((brg, ev)))
        match (brg, ev):
            # We need to update when we get rename events from parent qnames too.
            case (_, qname.RenameEvent(qname=qn, old_name=old_name, new_name=new_name)):
                DINFO("\tType renamed from {} to {}".format(old_name, new_name))
                self._handle_ty_rename(qn, old_name, new_name)
            case (qname.BRG_CHILDREN, qname.ChildMoveEvent(qname=qn, old_name=old_name, new_name=new_name)):
                DINFO("\tChildMoveEvent: {!r}".format((old_name, new_name)))
                # Note: if in the future, not all types in the context are
                # rendered in the editor, then we need to check that the type
                # being moved here is a type that we are rendering.
                self._handle_ty_rename(qn, old_name, new_name)
            case (event.BRG_ORIGIN, qname.EntityChangeEvent(qname=qn)):
                # XXX: Eventually, only re-render the requesting view, and not
                # the entire editor.
                DINFO("\tEntity change detected in {}".format(qn.fullname))
                self.render()
            case _:
                pass
        #endmatch
    #enddef

    def move_ty(self, old_fullname, new_fullname):
        self.ctx.move(old_fullname, new_fullname)
    #enddef    

    def do_user_add_ty(self):
        # XXX: Eventually, this should ask for the type to be created as well
        DINFO("Calling do_user_add_ty:")
        ty_name = idaapi.ask_str("", 230, "Type name: ")
        if ty_name == None:
            DINFO("\tCancelled by user.")
            return
        #endif

        if ty_name in self.ctx:
            DWARN("\tCannot add type, name '{}' already exists in context.".format(ty_name))
            idaapi.warning("Cannot add type, name '{}' already exists in context.".format(ty_name))
            return
        #endif

        # XXX: Should also check that ty_name is not a reserved keyword or a primitive type name.
        
        # XXX: Only creating Structs for now
        new_ty = T.Struct([(0, "field_000", T.UInt32)])

        DINFO("\tAdding to context.")
        self.ctx.add(ty_name, new_ty)
        # Note: Since the editor is observing context events, it will
        # automatically add a new viewer for the added type.

        # Call asynchronously because the viewer will only be added to the
        # editor after the event handling code runs.
        async def _do_jump():
            from . import event
            await event.manager.wait_till_queue_empty()
            self.jump_to_ty(ty_name)
        #enddef
        asyncio.get_event_loop().create_task(_do_jump())
        
    #endef
    
    def OnKeydown(self, vkey, shift):
        rv = super().OnKeydown(vkey, shift)
        DBG("OnKeydown: rv = {!r}".format(rv))
        DBG("\t(vkey, shift) = {!r}".format((vkey, shift)))
        DBG("\tIn map: {!r}".format((vkey, shift) in GLOBAL_KEY_MAP))
        # Handle global key bindings
        if not rv and (vkey, shift) in GLOBAL_KEY_MAP:
            action_code = GLOBAL_KEY_MAP[(vkey, shift)]
            DBG("\taction_code = {!r}".format(action_code))
            
            match action_code:
                case ActionCode.ADD_TYPE:
                    self.do_user_add_ty()
                    return True
                case ActionCode.POP_HISTORY:
                    self.pop_history()
                    return True
                case _:
                    return False
            #endmatch
                
        else:
            return rv
        #endif
        
    #enddef

    def Show(self):
        super().Show()
        self.render()
        idaapi.set_dock_pos(self._window_title, "Local Types", idaapi.DP_TAB)
    #enddef
    

#endclass
