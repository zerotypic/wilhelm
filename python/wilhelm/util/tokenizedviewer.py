#
# tokenizedviewer : TokenizedViewer custom viewer
#

from dataclasses import dataclass
from typing import Tuple, Dict, Optional

import idaapi

from . import disptokens
from .disptokens import Token, LineSepToken, DispToken, LinkedToken
from . import setup_logger

class Exn(Exception): pass
class UnimplementedExn(Exn): pass
class InvalidLinePositionExn(Exn): pass
class UnknownViewNameExn(Exn): pass
class ViewNameExistsExn(Exn): pass

__all__ = ("View", "TokenizedViewer")

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = setup_logger(__name__)

class View(object):
    '''Abstract base class of tokenized views of objects.
    '''

    def __init__(self, name, viewer):
        self._name = name
        self._viewer = viewer
        self.lookup_map = []
    #enddef

    @property
    def name(self): return self._name

    @name.setter
    def name(self, new_name):
        # _name gets updated by the viewer for us.
        self._viewer.update_view_name(self, new_name)
    #enddef

    def get_start_offset(self):
        '''Returns the number of lines at which the view "really"
        starts. Allows the viewer to skip any preambles that might be
        prepended to the view.'''
        return 0
    #enddef
    
    def to_disptokens(self):

        '''Generates a list of display tokens representing the object.'''
        raise UnimplementedExn("Must be implemented by subclass.")
    #enddef

    def render(self):
        '''Renders the object into a list of strings, one for each line.
        '''
        self.lookup_map = []
        toklist = self.to_disptokens()
        lines = []
        curline = []
        for tok in toklist:
            match tok:
                case LineSepToken():
                    lines.append(curline)
                    curline = []
                case _:
                    curline.append(tok)
            #endmatch
        #endfor
        if curline != []: lines.append(curline)

        rendered_lines = []
        for line in lines:
            tok_disps = [(tok, tok.display()) for tok in line]
            rendered_lines.append("".join([s for (_, s) in tok_disps]))
            # Note: use tag_strlen here as the string might contain color
            # escape sequences.
            self.lookup_map.append([(idaapi.tag_strlen(s), tok) for (tok, s) in tok_disps])
        #endfor

        return rendered_lines
        
    #enddef

    def get_token_at_pos(self, x, y):
        line = self.lookup_map[y]
        cur = 0
        for (chars, tok) in line:
            cur += chars
            if cur > x: return tok
        #endfor
        return line[-1][1]
    #enddef

    def handle_action(self, action_code, token):
        '''Handle an action.'''
        raise UnimplementedExn("Must be implemented by subclass.")
    #enddef

    def on_action(self, action_code, x, y):
        DBG("View.on_action: {!r}".format((action_code, x, y)))
        token = self.get_token_at_pos(x, y)
        DBG("\tGot token: {!r}".format(token))
        return self.handle_action(action_code, token)
    #enddef

    def focus_view(self):
        self._viewer.jump_to_view(self.name)
    #enddef
    
#endclass

@dataclass
class ViewInfo:
    view : View
    line_range : Tuple[int, int] = (None, None)
    extra : Optional[Dict] = None
#endclass

class TokenizedViewer(idaapi.simplecustviewer_t):

    # XXX TODO: Support mouse clicks.
    
    def __init__(self, key_map, view_sep=None):
        self._key_map = key_map
        self._view_info_map = {}
        self._view_ordering = []
        self._view_sep = view_sep
        self._history_stack = []
    #enddef

    def setup_view_info(self, vi):
        '''Initializes a new ViewInfo object.
        Subclasses should overload this if they need to setup the object in any way.
        '''
        return vi
    #enddef

    def add_view(self, view : View, render=True):
        if view.name in self._view_info_map:
            raise ViewNameExistsExn("Viewer already has a view with name '{}'".format(view.name))
        #endif

        if render: locinfo = self._save_current_location()
        
        vi = self.setup_view_info(ViewInfo(view))
        self._view_info_map[view.name] = vi
        self._view_ordering.append(view.name)

        if render:
            self.render()
            self._restore_location(locinfo)
        #endif
        
    #enddef

    def remove_view(self, view_name : str, render=True):
        if not view_name in self._view_info_map:
            raise UnknownViewNameExn("Cannot remove view with unknown name {}".format(view_name))
        #endif

        if render: locinfo = self._save_current_location()

        DINFO("Removing view {!r}".format(view_name))
        self._view_ordering.remove(view_name)
        del self._view_info_map[view_name]
        
        if render:
            self.render()
            self._restore_location(locinfo)
        #endif
    #enddef
    
    def has_view(self, view_name : str): return view_name in self._view_info_map
    
    def get_view(self, view_name : str): return self._view_info_map[view_name].view
    
    def jump_to_view(self, view_name : str, add_to_history=True):
        if view_name in self._view_info_map:
            vi = self._view_info_map[view_name]
            start_offset = vi.view.get_start_offset()
            DINFO("jump_to_view: jumping to {!r}".format(vi.line_range[0] + vi.view.get_start_offset()))
            self.Jump(vi.line_range[0] + start_offset, 0, start_offset)
        else:
            raise UnknownViewNameExn("Unknown view with name {}".format(view_name))
        #endif
    #enddef

    def push_history(self, view):
        DBG("push_history: history_stack = {!r}".format(self._history_stack))
        self._history_stack.append(view)
    #enddef
    
    def pop_history(self):
        DBG("pop_history: history_stack = {!r}".format(self._history_stack))
        if self._history_stack == []: return
        view = self._history_stack.pop()
        # Sanity check to make sure view is still part of viewer.
        if self.has_view(view.name):
            DBG("\tJumping to view {}".format(view.name))
            self.jump_to_view(view.name)
        else:
            # Ths view disappeared, try the one before.
            DBG("\tView disappeared, trying again.")
            self.pop_history()
        #endif
    #enddef
    
    def _swap_view_order(self, i):
        o = self._view_ordering
        self._view_ordering = o[:i] + o[i+1:i+2] + [o[i]] + o[i+2:]
    #enddef
    
    def shift_view_down(self, view_name : str):
        locinfo = self._save_current_location()
        self._swap_view_order(self._view_ordering.index(view_name))
        self.render()
        self._restore_location(locinfo)
    #enddef

    def shift_view_up(self, view_name : str):
        idx = self._view_ordering.index(view_name)
        if idx > 0:
            locinfo = self._save_current_location()
            self._swap_view_order(idx - 1)
            self.render()
            self._restore_location(locinfo)
        #endif
    #enddef
    
    def update_view_name(self, view : View, new_name : str):
        if new_name in self._view_info_map:
            raise ViewNameExistsExn("Cannot update, another view with name '{}' already exists.".format(new_name))
        #endif

        DINFO("update_view_name: {!r}".format((view, new_name)))
        old_name = view.name
        self._view_info_map[new_name] = self._view_info_map[old_name]
        del self._view_info_map[old_name]
        idx = self._view_ordering.index(old_name)
        self._view_ordering[idx] = new_name
        view._name = new_name
        self.render()
    #enddef

    def _save_current_location(self):
        (lineno, x, y) = self.GetPos()
        vi = self._get_view_info_at_line(lineno)
        view_offset = lineno - vi.line_range[0]
        return (vi.view.name, view_offset, x, y)
    #enddef

    def _restore_location(self, locinfo):
        (view_name, view_offset, x, y) = locinfo
        if view_name in self._view_info_map:
            vi = self._view_info_map[view_name]
            lineno = vi.line_range[0] + view_offset
            self.Jump(lineno, x, y)
        #endif
    #enddef
    
    def render(self):
        self.ClearLines()
        cur_line = 0
        for view_name in self._view_ordering:
            vi = self._view_info_map[view_name]
            lines = vi.view.render()
            if self._view_sep: lines += self._view_sep.splitlines()
            start_line = cur_line
            for l in lines:
                self.AddLine(l)
                cur_line += 1
            #endfor
            vi.line_range = (start_line, cur_line)
        #endfor
    #enddef

    def _get_view_info_at_line(self, lineno):
        for vi in self._view_info_map.values():
            (view_start, view_end) = vi.line_range
            if lineno >= view_start and lineno < view_end:
                return vi
            #endif
        #endfor
        raise InvalidLinePositionExn("No view at line position {!r}.".format(lineno))
    #enddef
    
    def OnKeydown(self, vkey, shift):
        DBG("TokenizedViewer.OnKeydown.")
        if (vkey, shift) in self._key_map:
            action_code = self._key_map[(vkey, shift)]
            (lineno, x, y) = self.GetPos()
            try:
                vi = self._get_view_info_at_line(lineno)
                # Perform action
                vi.view.on_action(action_code, x, lineno - vi.line_range[0])
                # Return True, because the action is considered to have been
                # handled, even if on_action() fails in some way.
                return True
            except InvalidLinePositionExn as exn:
                # Probably at some boundary or separator, ignore.
                DBG("\tCouldn't find view at cursor position, ignoring.")
                return False
            #endtry
        else:
            DBG("\tUnknown key, ignoring: {!r}".format((vkey, shift)))
            return False
        #endif
    #enddef
    
#endclass
