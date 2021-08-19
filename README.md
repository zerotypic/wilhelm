wilhelm : Alternative API for IDA and Hex-Rays
==============================================

wilhelm is an API for working with IDA, and in particular the Hex-Rays
decompiler. It aims to wrap around the existing SDK's API, plus provide
additional features and concepts that make reverse engineering easier.

## Example Usage

Initialize:
```python
>>> import wilhelm as W
>>> W.initialize(Feature.PATH, Feature.MODULE)
```

Access the AST of some function in the current module:
```python
>>> func = W.current().values["sub_12345"]().func
>>> func.body[0]
<wilhelm.ast.IfStmt at 0xXXXXXXXXXXXX>

>>> func.body[0].expr.op
<OP.UGT: 32>
```

Find all call expressions in the function:
```python
>>> list(func.select("*/CallExpr"))
[<wilhelm.ast.CallExpr at 0xXXXXXXXXXXXX>,
 <wilhelm.ast.CallExpr at 0xXXXXXXXXXXXX>,
 <wilhelm.ast.CallExpr at 0xXXXXXXXXXXXX>,
 <wilhelm.ast.CallExpr at 0xXXXXXXXXXXXX>,
 <wilhelm.ast.CallExpr at 0xXXXXXXXXXXXX>]
```

Get the names of the callee of the call expressions:
```python
>>> [W.current().get_qname_for_addr(e.addr) for e in func.select("*/CallExpr.e_func/")]
[QName<sub_15AC70>, QName<sub_15BE70>, QName<sub_15BE70>]
```

Get all calls expressions that are calling function at address `0x43213`:
```python
>>> calls = func.select("*/CallExpr[.e_func/GlobalVarExpr{addr = 0x43213}]"
>>> list(calls)
[<wilhelm.ast.CallExpr at 0xXXXXXXXXXXXX>,
 <wilhelm.ast.CallExpr at 0xXXXXXXXXXXXX>,
 <wilhelm.ast.CallExpr at 0xXXXXXXXXXXXX>]
```

Get string value of 2nd argument to the above calls:
```python
>>> [e.params[1].value for e in calls if isinstance(e.params[1], W.ast.StrExpr)]
[b'command', b'description']
```

## Dependencies

wilhelm requires a working async event loop in IDAPython. The easiest way to
get this is by installing `qasync`, which provides a Qt-based event loop. This
loop must be initialized prior to loading wilhelm.

The optional `path` feature requires `pyparsing`.

## Installation

wilhelm has yet to be properly packaged. For now, you can use it by cloning
the repository and adding the python/ subdirectory to your `sys.path` somehow.

Note that you need an async event loop setup before you load wilhelm. If
you're using qasync, you can add something like this to your `idapythonrc`:

```python
# Sync asyncio and Qt event loop
from PyQt5.QtWidgets import QApplication
import qasync
import asyncio
qapp = QApplication.instance()
loop = qasync.QEventLoop(qapp, already_running=True)
asyncio.set_event_loop(loop)
```

## Configuration

```python
import wilhelm as W
W.initialize()                             # Init with only core features
# or:
W.initialize(Feature.PATH, Feature.MODULE) # Init with optional features
```

## Features

### Abstract Syntax Tree Access

wilhelm provides a more object-oriented/Pythonic way of accessing a decompiled
function's AST. Nodes in the AST have a different class based on the kind of
nodes they are, and expose relevant values as fields. A Visitor class can be
used to traverse the AST.

A NodeList represents a collection of AST nodes, and provides ways of mapping and
filtering the list. This can be used to quickly locate a specific code of
interest.

### AST Wilpaths

The optional `path` feature provides /wilpaths/, which are a way to easily
navigate and select nodes in an AST. Inspired by the XPath query language for
XML, a wilpath builds upon the filtering and mapping features of NodeLists.

Some examples of wilpaths:

* `IfStmt`
  Returns all if statements found in the current node list.

* `/IfStmt`
  Returns all children that are if statements.

* `*/IfStmt`
  Returns any descendent that is an if statement.

* `*/IfStmt.expr/`
  Returns the condition expression of all if statement descendents.

* `*/IfStmt.expr/*/GlobalVarExpr`
  Returns all global variable expressions that are found within an if
  statement.

* `*/IfStmt.expr/*/GlobalVarExpr{addr = 0x1234}`
  The above, but only those global variable expressions which have an
 address of 0x1234.

* `*/IfStmt[.expr/*/GlobalVarExpr{addr = 0x1234}]`
  The above, but instead of returning the global variable expressions,
  return the parent if statement.

Please see the docstring in python/wilhelm/path.py for a complete description
of the wilpath DSL.

### Event System

wilhelm uses an event system that allows users to register and observe various
kinds of events happening within IDA. For example, a callback can be added to
trigger whenever some property of a function changes.

Events can propagate, such that one could observe all events happening the
children of a parent object, and vice versa.

Currently, the event system is only integrated with the naming system
(QNames), but eventually will be available in other features as well,
particularly the type system.

### Module Representation

The `module` feature provides a way of accessing the currently-loaded IDA
database (aka module). All objects in the database have an associated
/qualified name/ (QName), which is kept in sync with the name used by
IDA. QNames allow navigation and searching based on their structure: e.g. you
can query for all names that are in a particular namespace like
`foo::SomeClass`. Renaming a namespace also automatically updates the names
within that namespace.

Querying a name returns a representation of the object. For functions, the AST
of the function can be easily accessed via this representation:

```python
wilhelm.current().values["sub_12345"]().func.body[0].expr.e_lhs
```

The module feature is currently in development, and hence optional, but it
will eventually form a core part of wilhelm.

## Credits

TODO

### License

GNU General Public License v3.0

See [LICENSE](/LICENSE) for full text.
