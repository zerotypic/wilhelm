'''
path : XPath-style AST navigation and selection.

A wilpath consists of a series of selectors. There are two kinds of
selectors, navigators and filters.

A navigator selector navigates through the nodes in the list in a specific
way and returns the resultant nodes. There are 3 kinds of navigators:

- Child navigator: /
  Returns all the direct children of the nodes in the list.

- Descendant navigator: */
  Returns all descendents of the nodes in the list, including the nodes
  themselves.

- Attribute navigator: .<attribute>/
  Returns a NodeList made up of all the nodes specified by the attribute
  <attribute> of each node in the list. <attribute> is expected to be a
  NodeList of nodes. <attribute> can also be a method call, of the form 
  <method>(<param>, ...), where <param> is a number or string.

  This can be used to return specific children of a node. For example:
  "CallExpr.e_func/" will return the function expression of all CallExprs
  in the NodeList.


A filter selector filters the nodes in the list to return only those that
meet a specified condition. There are 3 kinds of filters:

- Class filter: <classname>
  Returns all nodes in the list which are an instance of
  <classname>. <classname> must be a subclass of ast.Node, and be found in
  the ast module.

- Attribute filter: {<attribute-test>}
  where <attribute-test> is: <attribute>
                         or: <attribute> <comparator> <value>
  Returns all nodes which have an attribute <attribute> for which the test
  is true. If the test consists of just the attribute itself, then the
  attribute is expected to be a boolean value reflecting the result of the
  test. If not, then it tests if the attribute matches the specified
  <value> based on the <comparator>. For example, {addr = 0x1234} returns
  all nodes which have an "addr" attribute that is set to 0x1234.

  <attribute> can also be a method call, of the form
  <method>(<param>, ...), where <param> is a number or string.

  Available comparators are: =, !=, <, > , <=, >=

  The value must be either a number, or a string quoted using single
  quotes (').

- Subpath filter: [<sub-path>]
  Returns all nodes for which the wilpath <sub-path> returns one or more
  nodes. For example: "CallExpr[*/LocalVarExpr]" returns all CallExprs
  that contain a LocalVarExpr.

Some examples to get you started:

- "IfStmt"
  Returns all if statements found in the current node list.

- "/IfStmt"
  Returns all children that are if statements.

- "*/IfStmt"
  Returns any descendent that is an if statement.

- "*/IfStmt.expr/"
  Returns the condition expression of all if statement descendents.

- "*/IfStmt.expr/*/GlobalVarExpr"
  Returns all global variable expressions that are found within an if
  statement.

- "*/IfStmt.expr/*/GlobalVarExpr{addr = 0x1234}"
  The above, but only those global variable expressions which have an
  address of 0x1234.

- "*/IfStmt[.expr/*/GlobalVarExpr{addr = 0x1234}]"
  The above, but instead of returning the global variable expressions,
  return the parent if statement.
'''

import pyparsing as pp
import operator
from types import MethodType

from . import ast

# __all__ = ["compile"]

class Exn(Exception): pass

# TODO:
# - Try changing from using lambdas to using some (command, args) tuple, and
#   have the calls take place in a loop in NodeList.select(). See if this
#   is more efficient than lambdas.
#

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

#
# Parser combinators start here.
#

WilPath = pp.Forward()

Identifier = pp.Word(pp.alphas + "_", bodyChars=pp.alphanums + "_")
ClassName = Identifier.copy()
ChildName = Identifier.copy()
AttributeName = Identifier.copy()

@parser((pp.Combine(pp.Literal("0x") + pp.Word(pp.hexnums))) |
        (pp.Combine(pp.Literal("0b") + pp.Word("01"))) |
        (pp.Combine(pp.Literal("0") + pp.Word("01234567"))) |
        pp.Word(pp.nums)
    )
def Num(tok):
    return int(tok[0], base=0)
#enddef

Value = Num | pp.QuotedString("'", escChar="\\")

@parser(AttributeName + pp.Optional(
    pp.Literal("(") +
    pp.Group(pp.Optional(pp.delimitedList(Value, delim=","))) +
    pp.Literal(")")))
def Attribute(tok):
    params = tok[2].asList() if len(tok) > 1 else None
    return (tok[0], params)
#enddef

_OPERATORS = {
    "=" : operator.eq,
    "!=" : operator.ne,
    ">" : operator.gt,
    "<" : operator.lt,
    ">=" : operator.ge,
    "<=" : operator.le,
}

@parser(pp.oneOf(_OPERATORS.keys()))
def Comparator(tok):
    return _OPERATORS[tok[0]]
#enddef

@parser(Attribute + pp.Optional(Comparator + Value))
def AttributeTest(tok):
    (attr_name, params) = tok[0]
    if len(tok) == 1:
        # Test on this attribute only.
        return lambda n: n._access_attribute(attr_name, params)
    else:
        compfunc = tok[1]
        value = tok[2]
        return lambda n: compfunc(n._access_attribute(attr_name, params), value)
    #enddef
#enddef

@parser(pp.Literal("/"))
def AllChildNavigator(tok):
    return lambda nl: nl.children()
#enddef

#@parser(pp.White())
@parser(pp.Literal("*/"))
def AllNavigator(tok):
    return lambda nl: nl.all()
#enddef

@parser(pp.Literal(".") + Attribute + pp.Literal("/"))
def AttributeNavigator(tok):
    (attr_name, params) = tok[1]
    return lambda nl: nl.map_attr(attr_name, params)
#enddef

@parser(ClassName)
def ClassFilter(tok):
    clsname = tok[0]
    cls = getattr(ast, clsname)
    assert(issubclass(cls, ast.Node))
    return lambda nl: nl.filter_class(cls)
#enddef

@parser(pp.Literal("{") + AttributeTest + pp.Literal("}"))
def AttributeFilter(tok):
    return lambda nl: nl.filter_test(tok[1])
#enddef

@parser(pp.Literal("[") + WilPath + pp.Literal("]"))
def SubpathFilter(tok):
    (_, subpath_func, _) = tok
    def testfunc(n):
        return list(subpath_func(ast.NodeList([n]))) != []
    #enddef
    return lambda nl: nl.filter_test(testfunc)
#enddef

Selector = AllNavigator | AllChildNavigator | AttributeNavigator | \
           ClassFilter | AttributeFilter | SubpathFilter

WilPath << pp.OneOrMore(Selector)

def _WilPath_action(tok):
    def _func(nl):
        for func in tok: nl = func(nl)
        return nl
    #enddef
    return _func
#enddef
WilPath.setParseAction(_WilPath_action)

def compile(pathstr):
    return WilPath.parseString(pathstr, parseAll=True)[0]
#enddef

# Monkey-patch AST module to add 'select' functions.

def _NodeList_select(self, pathstr):
    return compile(pathstr)(self)
#enddef
ast.NodeList.select = _NodeList_select

def _Function_select(self, pathstr):
    return self.body.children.select(pathstr)
#enddef
ast.Function.select = _Function_select

def _Node_select(self, pathstr):
    nl = ast.NodeList([self])
    assert(isinstance(self, ast.Node))
    return nl.select(pathstr)
#enddef
ast.Node.select = _Node_select

def _BlockStmt_select(self, pathstr):
    return self.children.select(pathstr)
#enddef
ast.BlockStmt.select = _BlockStmt_select

