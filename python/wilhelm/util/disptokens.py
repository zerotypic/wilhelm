#
# disptokens : Tokens used for displaying structured information
#

import itertools

import idaapi

from .singleton import SingletonMeta

class Token(object):
    def __repr__(self): return "<{}>".format(self.__class__.__name__)

    def is_linked(self): return isinstance(self, LinkedToken)

    @classmethod
    def add_seps(self, tokenlist):
        return itertools.chain(*(
            (token, Token.SEP())
            for token
            in tokenlist
        ))
    #enddef
    
#endclass

class LineSepToken(Token, metaclass=SingletonMeta): pass

class WhitespaceToken(Token):
    def __init__(self, n):
        self.n = int(n)
    #enddef
    def display(self): return " " * self.n
    def __repr__(self): return "<{}: {:d}".format(self.__class__.__name__, self.n)
#endclass

class DispToken(Token):
    # Can be set by subclasses to change the default token colour
    _color = None
    def __init__(self, s, addspace=False, color=None):
        self.string = s
        self.addspace = addspace
        if color != None: self._color = color
    #enddef

    def display(self):
        disp = self.string
        if self._color != None: disp = idaapi.COLSTR(disp, self._color)
        if self.addspace: disp += " "
        return disp
    #enddef

    def __repr__(self): return "<{} '{}'>".format(self.__class__.__name__, self.string)
#endclass

class LinkedToken(DispToken):
    def __init__(self, s, obj, **kwargs):
        super().__init__(s, **kwargs)
        self.obj = obj
    #enddef
#endclass

Token.SEP = LineSepToken
Token.DISP = DispToken
Token.LINK = LinkedToken
