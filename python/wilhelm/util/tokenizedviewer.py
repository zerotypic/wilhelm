#
# tokenizedviewer : TokenizedViewer custom viewer
#

import idaapi

class Exn(Exception): pass

class Token(object):
    def __repr__(self): return "<{}>".format(self.__class__.__name__)
#endclass

class LineSepTokenMeta(type):
    _singleton = None
    def __call__(cls, *args, **kwargs):
        if cls._singleton == None:
            cls._singleton = super().__call__(*args, **kwargs)
        #endif
        return cls._singleton
    #enddef
#endclass
class LineSepToken(Token, metaclass=LineSepTokenMeta): pass

class DispToken(Token):
    def __init__(self, v):
        self.value = v
    #enddef
    def display(self): return self.value
    def __repr__(self): return "<{} '{}'>".format(self.__class__.__name__, self.display())
#endclass

class ActableToken(DispToken):
    def __init__(self, v, action):
        super().__init__(v)
        self.action = action
    #enddef
    def act(self, *args, **kwargs):
        return self.action(*args, **kwargs)
    #enddef
#endclass

Token.SEP = LineSepToken
Token.DISP = DispToken
Token.ACT = ActableToken

class View(object):
    def render(self): pass
#endclass

class TokenizedViewer(idaapi.simplecustviewer_t):

    # XXX TODO: Support mouse clicks.
    
    def __init__(self, key_map):
        self.lookup_map = []
        self.key_map = key_map
    #enddef

    def set_view(self, view):
        self.view = view
    #enddef
    
    def render(self):
        self.lookup_map = []
        self.ClearLines()

        toklist = self.view.render()
        lines = []
        curline = []
        for tok in toklist:
            if isinstance(tok, LineSepToken):
                lines.append(curline)
                curline = []
            else:
                curline.append(tok)
            #endif
        #endfor
        if curline != []: lines.append(curline)
        
        for line in lines:
            tok_disps = [(tok, tok.display()) for tok in line]
            rendered_line = " ".join([s for (_, s) in tok_disps])
            self.AddLine(rendered_line)
            self.lookup_map.append([(len(s), tok) for (tok, s) in tok_disps])
        #endfor
    #enddef

    def get_current_token(self):
        (_, x, y) = self.GetPos()
        line = self.lookup_map[y]
        cur = 0
        for (chars, tok) in line:
            cur += chars + 1
            if cur > x: return tok
        #endfor
        return line[-1][1]
    #enddef

    def OnKeydown(self, vkey, shift):
        if (vkey, shift) in self.key_map:
            action_code = self.key_map[(vkey, shift)]
            tok = self.get_current_token()
            if isinstance(tok, ActableToken):
                tok.act(action_code)
            #endif
        #endif
    #enddef
    
#endclass
