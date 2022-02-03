#
# qname : Qualified names for wilhelm
#

import itertools
import re
import asyncio

from . import event
from . import util
from .util import TYPECHECK, TypecheckExn
from .util.immutable import immdict
from .util import asyncutils

class Exn(Exception): pass
class InvalidBasenameExn(Exn): pass
class DuplicateNameExn(Exn): pass
class SQNameConflictExn(Exn): pass
class SQNameChildExn(Exn): pass
class NotFoundExn(Exn): pass
class SearchExn(Exn): pass
class OrphanedExn(Exn): pass

__all__ = ("Root", "QName", "Context")

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = util.setup_logger(__name__)

_DELIMITER = "::"
_SUFFIX_DELIMITER = "$$"

# XXX: TODO Optimize and make more memory-efficient.

# QNameEvents are always tagged by the name of their context.
class QNameEvent(event.Event):
    '''Events related to qnames.

    If you want to handle all instances where a qname is renamed,
    you must listen for:
    - RenameEvent emitted by the qname
    - ChildMoveEvent emitted by the current *parent* (i.e. you must
    register as a relay event observer)
    
    If you want to handle all instances where a qname's list of children
    changes, you must listen for:
    - AddChildEvent emitted by the qname
    - RemoveChildEvent emitted by the qname
    - ChildMoveEvent emitted by the qname

    '''
    def __init__(self, ctx, **kwargs):
        super().__init__(tag=ctx.name, **kwargs)
        self.ctx = ctx
    #enddef
#endclass

class AddChildEvent(QNameEvent):
    '''Triggered after the child is added.'''
    def __init__(self, ctx, parent, childname, **kwargs):
        super().__init__(ctx, **kwargs)
        self.parent = parent
        self.childname = childname
    #enddef
#endclass

class RemoveChildEvent(QNameEvent):
    '''Triggered before the child is removed.'''
    def __init__(self, ctx, parent, childname, **kwargs):
        super().__init__(ctx, **kwargs)
        self.parent = parent
        self.childname = childname
    #enddef
#endclass

class OrphanEvent(QNameEvent):
    '''Triggered before a qname is orphaned (deleted).'''
    def __init__(self, ctx, qname, **kwargs):
        super().__init__(ctx, **kwargs)
        self.qname = qname
    #enddef
#endclass

class RenameEvent(QNameEvent):
    '''Triggered after a qname is renamed.'''
    def __init__(self, ctx, qname, old_name, new_name, **kwargs):
        super().__init__(ctx, **kwargs)
        self.qname = qname
        self.old_name = old_name
        self.new_name = new_name
    #enddef
#endclass

class ChildMoveEvent(QNameEvent):
    '''Triggered after a qname is moved from one parent to another, and
    optionally renamed.
    This event will be emitted by both the old parent and the new parent.'''
    def __init__(self, ctx, qname, old_parent, new_parent, old_name, new_name, **kwargs):
        super().__init__(ctx, **kwargs)
        self.qname = qname
        self.old_parent = old_parent
        self.new_parent = new_parent
        self.old_name = old_name
        self.new_name = new_name
    #enddef
#endclass

class EntityChangeEvent(QNameEvent):
    '''Triggered whenever a qname's entity is set.'''
    def __init__(self, ctx, qname, **kwargs):
        super().__init__(ctx, **kwargs)
        self.qname = qname
    #enddef
#endclass

# Bearings for qnames
BRG_PARENT = event.Bearing("qname.parent")
BRG_CHILDREN = event.Bearing("qname.children")

@event.Relay.register(BRG_PARENT, BRG_CHILDREN)
class Root(event.Relay):

    def __init__(self, ctx):
        TYPECHECK(ctx, Context)
        self._ctx = ctx
        self._children = {}
        super().__init__()
    #enddef

    def __str__(self): return "<root>"
    def __repr__(self): return "Root<%s>" % self._ctx.name

    def _join(self, s): return s

    @BRG_PARENT.adjacents_property
    def parent(self): return None
    
    @property
    def children(self): return immdict(self._children)

    @BRG_CHILDREN.adjacents_property
    def children_list(self): return self.children.values()

    def __len__(self): return len(self._children)
    def __getitem__(self, key): return self._children[key]
    def __iter__(self): return iter(self.children)
    def __contains__(self, item): return item in self._children
    
    def descendents(self):
        '''Returns all descendents, including self.'''
        yield self
        for c in self._children.values():
            for d in c.descendents(): yield d
        #endfor
    #enddef

    def terminals(self, filter_entity_type=None):
        '''Returns all terminal descendents.'''
        for c in self.descendents():
            if not issubclass(type(c), QName): continue
            if not c.is_terminal: continue
            if filter_entity_type != None:
                if not issubclass(type(c.entity), filter_entity_type): continue
            #endif
            yield c
        #endfor
    #enddef

    def _check_duplicate_name(self, name):
        if name in self._children:
            raise DuplicateNameExn("Name %s already present in namespace %s" % (name, repr(self)))
        #endif
    #enddef

    def _add_child(self, child):
        self._children[child._basename] = child
    #enddef

    def _remove_child(self, child):
        del self._children[child._basename]
    #enddef
    
    def add_child(self, child_basename, caused_by=None):
        '''Creates and returns a new child to this namespace with basename 'child_basename'.'''
        self._check_duplicate_name(child_basename)
        new_child = QName(self._ctx, self, child_basename)
        self._add_child(new_child)
        self.emit_event(AddChildEvent, self._ctx, self, child_basename, cause=caused_by)
        return new_child           
    #enddef

    async def remove_child_async(self, child_basename, caused_by=None):
        '''Removes the child with basename 'child_basename' from this
        namespace. The child object becomes an orphaned QName and cannot
        be used.'''
        if child_basename in self._children:
            child = self._children[child_basename]
            self._ctx._is_clean_event.clear()
            await self._orphan_child(child, caused_by=caused_by)
            self._ctx._is_clean_event.set()
        else:
            raise NotFoundExn("Cannot find child '{}' to delete.".format(child_basename))
        #endif        
    #enddef

    def remove_child(self, child_basename, caused_by=None):
        return asyncutils.run_task_till_done(self.remove_child_async(child_basename, caused_by=caused_by))
    #enddef
    
    async def _orphan_child(self, child, caused_by=None):
        DBG("Orphaning child: %r", child)
        # Begin orphaning from leaf nodes upwards.
        children = list(child.children.values())
        for c in children: await child._orphan_child(c, caused_by=caused_by)

        # Wait for event handlers to finish before we remove the child, so
        # they can access the child before it gets orphaned.
        await self.emit_event_and_wait(RemoveChildEvent, self._ctx, self, child._basename, cause=caused_by)
        await child.emit_event_and_wait(OrphanEvent, child._ctx, child, cause=caused_by)
        DBG("\tEvent handlers completed, performing orphan operation.")
        child_basename = child._basename
        self._remove_child(child)
        child._old_fullname = child.fullname
        child._basename = None
        child._parent = None
        child._entity = None       
        child.__class__ = OrphanedQName
        
    #enddef

    # Adopts a child by removing it from its existing parent and adding it
    # as a child to this node. Optionally, renames the child before adding.
    def _adopt_child(self, new_child, new_name=None, caused_by=None):
        TYPECHECK(new_child, QName)
        if new_name == None:
            self._check_duplicate_name(new_child._basename)
        #endif
        new_child._ctx = self._ctx
        old_parent = new_child._parent
        old_name = new_child._basename

        # Check for duplicate names before we make any changes.
        if new_name != None and new_name != old_name:
            self._check_duplicate_name(new_name)
        #endif
        
        old_parent._remove_child(new_child)
        if new_name != None: new_child._basename = new_name
        new_child._parent = self
        self._add_child(new_child)

        # Emit events.
        old_parent.emit_event(ChildMoveEvent,
                              old_parent._ctx,
                              new_child,
                              old_parent,
                              self,
                              old_name,
                              new_name,
                              cause=caused_by)
        self.emit_event(ChildMoveEvent,
                        self._ctx,
                        new_child,
                        old_parent,
                        self,
                        old_name,
                        new_name,
                        cause=caused_by)

        return new_child

    #enddef

    def _rename_child(self, old_name, new_name, caused_by=None):
        self._check_duplicate_name(new_name)
        if not old_name in self._children:
            raise NotFoundExn("Cannot find child '{}' to rename.".format(old_name))
        #endif
        child = self._children[old_name]
        self._remove_child(child)
        child._basename = new_name
        self._add_child(child)
        child.emit_event(RenameEvent, child._ctx, child, old_name, new_name, cause=caused_by)
    #enddef
    
    async def clear_async(self, caused_by=None):
        children = list(self._children.values())
        self._ctx._is_clean_event.clear()
        for c in children: await self._orphan_child(c, caused_by=caused_by)
        self._ctx._is_clean_event.set()
    #enddef

    def clear(self, caused_by=None):
        asyncutils.run_task_till_done(self.clear_async(caused_by=caused_by))
    #enddef
    
    def search(self, query, **kwargs):
        return list(itertools.chain(*(child.search(query, **kwargs) for child in self._children.values())))
    #enddef

#endclass

@event.Relay.register(BRG_PARENT, BRG_CHILDREN)
class QName(Root):
    '''
    A qualified name (QName) is a name within a namespace. It consists of
    an identifier (basename), and a parent QName. Given a QName, its child
    QNames can also be determined. QNames are delimited using the "::"
    delimiter.
    
    QNames can contain a suffix, which is functionally part of the
    basename, but recognized by wilhelm for certain operations such as
    search. Suffixes allow representation of objects that might share the
    same name but are differentiated through some other means, e.g. by
    their type signature in overloaded functions.

    A QName can have an entity associated with it. This allows QNames to
    be used to store and lookup specific objects.
    '''
    
    def __init__(self, ctx, parent, basename, entity=None):
        if _DELIMITER in basename:
            raise InvalidBasenameExn("Cannot have delimiter (%s) in basename (%s)." % (_DELIMITER, basename))
        #endif
        
        TYPECHECK(parent, Root)

        super(QName, self).__init__(ctx)
        self._parent = parent
        self._basename = basename
        self._entity = entity
    #enddef

    def __str__(self): return self.fullname
    def __repr__(self): return "QName<{}>".format(str(self))

    def _join(self, s): return qns_join(self.fullname, s)
    
    @property
    def basename(self): return self._basename

    @basename.setter
    def basename(self, value): self.set_basename(value)
    
    @property
    def suffix(self):
        s = self.basename.split(_SUFFIX_DELIMITER, 1)
        return s[1] if len(s) == 2 else None
    #enddef

    @property
    def unsuffixed_basename(self):
        return self.basename.split(_SUFFIX_DELIMITER, 1)[0]
    #enddef

    @BRG_PARENT.adjacents_property
    def parent(self): return self._parent

    @parent.setter
    def parent(self, new_parent): self.set_parent(new_parent)
    
    @property
    def fullname(self): return self._parent._join(self.basename)

    @property
    def entity(self): return self._entity

    @entity.setter
    def entity(self, value): self.set_entity(value)

    @property
    def is_terminal(self): return len(self._children) == 0
    
    @property
    def is_orphaned(self): return self._parent == None

    def set_basename(self, new_basename, caused_by=None):
        self._parent._rename_child(self._basename, new_basename, caused_by=caused_by)
    #enddef
    
    def set_parent(self, new_parent, caused_by=None):
        TYPECHECK(new_parent, Root)
        if new_parent._ctx != self._ctx:
            print("WARNING: Changing to a parent with a different context!")
        #endif
        new_parent._adopt_child(self, caused_by=caused_by)
    #enddef  

    def set_entity(self, entity, caused_by=None):
        self._entity = entity
        self.emit_event(EntityChangeEvent, self._ctx, self, cause=caused_by)
    #enddef
    
    _search_re = re.compile("^(::|:\*:)?(.*?)((::|:\*:).*)?$")
    def search(self, query, only_terminal=True):
        '''
        Searches descendent qnames (including itself) for qnames matching <query>.
        '''

        m = self._search_re.match(query)
        if m == None: raise SearchExn("Error parsing search query: %s" % query)
        (joiner, term, trailing, _) = m.groups()
        term_re = re.compile(term)

        if joiner == None:
            searchlist = [self]
        elif joiner == "::":
            searchlist = self._children.values()
        elif joiner == ":*:":
            searchlist = self.descendents()
        #endif

        matches = [child for child
                   in searchlist
                   if term_re.match(child.basename)]

        if trailing == None:
            if only_terminal:
                return [m for m in matches if m.is_terminal]
            else:
                return matches
            #endif
        else:
            return list(set(itertools.chain(
                *(m.search(trailing, only_terminal=only_terminal)
                  for m in matches)))
            )
        #endif

    #enddef

#endclass

class OrphanedQName(QName):

    _old_fullname = "(unknown)"
    
    def __str__(self): return "ORPHAN<{}>".format(self._old_fullname)
    def __repr__(self): return "ORPHAN-QName<{}>".format(self._old_fullname)

    def _join(self, s): raise OrphanedExn("{} is orphaned.".format(repr(self)))
    
    @property
    def basename(self): raise OrphanedExn("{} is orphaned.".format(repr(self)))
    @property
    def suffix(self): raise OrphanedExn("{} is orphaned.".format(repr(self)))
    @property
    def unsuffixed_basename(self): raise OrphanedExn("{} is orphaned.".format(repr(self)))
    @property
    def parent(self): raise OrphanedExn("{} is orphaned.".format(repr(self)))
    @property
    def fullname(self): raise OrphanedExn("{} is orphaned.".format(repr(self)))
    @property
    def entity(self): raise OrphanedExn("{} is orphaned.".format(repr(self)))
    @entity.setter
    def entity(self, value): raise OrphanedExn("{} is orphaned.".format(repr(self)))
    @property
    def is_terminal(self): raise OrphanedExn("{} is orphaned.".format(repr(self)))
    @property
    def is_orphaned(self): return True
    
#endclass

                         
class Context(object):
    '''
    A naming context.
    '''
    
    def __init__(self, name):
        '''Creates a new naming context. <name> is used to identify the context.'''
        self._name = name
        self._root = Root(self)
        self._is_clean_event = asyncio.Event()
        self._is_clean_event.set()
    #enddef

    def __repr__(self): return "Context<%s>" % self.name
    
    @property
    def name(self): return self._name
    
    @property
    def root(self): return self._root

    async def wait_until_clean(self):
        await self._is_clean_event.wait()
    #enddef
    
    def terminals(self, filter_entity_type=None):
        return self._root.terminals(filter_entity_type=filter_entity_type)
    #enddef
    #
    # Internal function used to implement locate and build.
    # Notes:
    # - when gather_suffixes is True, look for all qnames that have the
    #   queried unsuffixed basename. Returns qnames are all terminal values.
    #
    def _locate(self, qns, build=False, gather_suffixes=False, caused_by=None):
        
        # Note: This list is guaranteed to contain at least 1 element.
        namelist = qns_split(qns)

        cur = self.root
        # Find our way to the direct parent of the node being located.
        for match_name in namelist[:-1]:
            if not match_name in cur.children:
                if build:
                    cur = cur.add_child(match_name, caused_by=caused_by)
                else:
                    return None
                #endif
            else:
                cur = cur.children[match_name]
            #endif
        #endwhile
              
        term_name = namelist[-1]
        if gather_suffixes:
            term_name = qns_unsuffixed_basename(term_name)
            suffixes = [c for c in cur.children.values()
                        if c.is_terminal and c.unsuffixed_basename == term_name]
            return suffixes if len(suffixes) > 0 else None
        else:
            if term_name in cur.children:
                return cur.children[term_name]
            elif build:
                return cur.add_child(term_name, caused_by=caused_by)
            else:
                return None
            #endif
        #endif
        
    #enddef

    def locate(self, qns, build=False, gather_suffixes=False, caused_by=None):
        qn = self._locate(qns, build=build,
                          gather_suffixes=gather_suffixes,
                          caused_by=caused_by)
        if qn == None:
            raise NotFoundExn("Could not find name {}".format(qns))
        #endif
        return qn
    #enddef
    
    def contains(self, qns):
        qn = self._locate(qns)
        return qn != None
    #enddef
    
    def build(self, qns, caused_by=None):
        return self._locate(qns, build=True, caused_by=caused_by)
    #enddef
    
    def search(self, query, **kwargs):
        '''
        Searches a context for specific qnames. The search <query> has the
        form "[regex][join-match]...", where [regex] is a regular
        expression matching an identifier, and [join-match] is one of the following:
            "::" --> matches direct parent and child identifiers
            ":*:" --> matches ancestor and descendent identifiers

        For example, "foo:*:bar" matches qnames "foo::hello::bar", "foo::this::is::bar",
        as well as "foo::bar".

        To match qnames with arbitrary parent identifiers, start the query with ":*:". 
        For example, ":*:foo" matches "this::is::foo", "also::foo" and "foo".
        '''
        return self.root.search(query, **kwargs)
    #enddef    

    def move(self, old_qns, new_qns, caused_by=None):
        '''
        Moves the qname identified by 'old_qname_str' to a new location on
        this context, identified by 'new_qname_str'.
        '''

        qn = self.locate(old_qns)
        
        new_parent_str = qns_parent(new_qns)
        new_basename = qns_basename(new_qns)

        if new_parent_str == "":
            # new parent is the root.
            new_parent = self.root
        else:
            new_parent = self.build(new_parent_str)
        #endif

        new_parent._check_duplicate_name(new_basename)
        
        if new_parent == qn.parent:
            # Locations have the same parent, can just do a rename.
            qn.parent._rename_child(qn.basename, new_basename, caused_by=caused_by)
        else:
            new_parent._adopt_child(qn, new_name=new_basename, caused_by=caused_by)
        #endif

    #enddef

    def __getitem__(self, key):
        v = self._locate(key, build=False)
        if v == None: raise KeyError(key)
        return v
    #enddef
    def __iter__(self): return iter(self.terminals())
    
#endclass

#
# Utility functions for manipulating qname strings (qns).
#

def qns_split(qns):
    return qns.split(_DELIMITER)
#enddef

def qns_join(qns, child_str):
    return qns + _DELIMITER + child_str
#enddef
    
def qns_basename(qns):
    return qns_split(qns)[-1]
#enddef

def qns_parent(qns):
    if _DELIMITER in qns:
        return qns.rsplit(_DELIMITER, 1)[0]
    else:
        return ""
    #endif
#enddef

def qns_suffix(qns):
    s = qns_basename(qns).split(_SUFFIX_DELIMITER, 1)
    return s[1] if len(s) == 2 else None
#enddef

def qns_unsuffixed_basename(qns):
    s = qns_basename(qns).split(_SUFFIX_DELIMITER, 1)
    return s[0]
#enddef

def qns_add_suffix(qns, suffix):
    return qns + _SUFFIX_DELIMITER + suffix
#enddef

#
# UNIT TESTS
#

import unittest

class Test(event.EventTestCase):

    def setUp(self):
        super().setUp()
    #enddef
        
    def tearDown(self):
        super().tearDown()
    #enddef

    def assertEventsMatch(self, events, specs,
                          includes_bearings=False,
                          include_origin=False):
        return super().assertEventsMatch(
            events, specs,
            includes_bearings=includes_bearings,
            include_origin=include_origin,
            ignore_props=("ctx",))
    #enddef
    
    def test_context(self):
        ctx = Context("test")
        self.assertEqual(ctx.name, "test")
        self.assertEqual(type(ctx.root), Root)
        self.assertEqual(len(ctx.root.children), 0)
    #enddef

    def test_root(self):
        ctx = Context("test")
        child = ctx.root.add_child("foo")
        self.assertEqual(type(child), QName)
        
        self.assertCountEqual(ctx.root.children.items(), [("foo", child)])
        self.assertEqual(child.parent, ctx.root)

        child2 = ctx.root.add_child("bar")
        self.assertCountEqual(ctx.root.children.items(), [
            ("foo", child),
            ("bar", child2)
        ])

        with self.assertRaises(DuplicateNameExn):
            ctx.root.add_child("foo")
        #endwith

        with self.assertRaises(TypeError):
            ctx.root.children["baz"] = child2
        #endwith        

        ctx.root.clear()
        self.assertEqual(len(ctx.root.children), 0)
        
    #enddef

    def test_root_traversal(self):
        ctx = Context("test")
        foo = ctx.root.add_child("foo")
        foo_ding = foo.add_child("ding")
        foo_gah = foo.add_child("gah")
        
        bar = ctx.root.add_child("bar")
        bar_ding = bar.add_child("ding")
        bar_ding_dong = bar_ding.add_child("dong")
        bar_boing = bar.add_child("boing")

        self.assertCountEqual(
            list(ctx.root.descendents()),
            [ctx.root,
             foo, foo_ding, foo_gah,
             bar, bar_ding, bar_ding_dong, bar_boing]
        )

        self.assertCountEqual(
            list(ctx.root.terminals()),
            [foo_ding, foo_gah, bar_ding_dong, bar_boing]
        )

        foo_ding.entity = "hi"
        foo_gah.entity = 10
        bar_ding_dong.entity = "bye"
        bar_boing.entity = [1,2,3]

        self.assertCountEqual(
            list(ctx.root.terminals(filter_entity_type=str)),
            [foo_ding, bar_ding_dong]
        )
        
    #enddef

    
    def test_qname(self):
        ctx = Context("test")
        foo = ctx.root.add_child("foo")
        self.assertEqual(foo.basename, "foo")
        self.assertEqual(foo.fullname, "foo")
        self.assertFalse(foo.is_orphaned)

        bar = foo.add_child("bar")
        self.assertEqual(bar.basename, "bar")
        self.assertEqual(bar.fullname, "foo::bar")

        with self.assertRaises(InvalidBasenameExn):
            foo.add_child("boing::x")
        #endwith

        boing = bar.add_child("boing")
        
        self.assertEqual(bar.suffix, None)
        self.assertEqual(bar.unsuffixed_basename, "bar")
        
        baz = foo.add_child("baz$$boing")
        self.assertEqual(baz.suffix, "boing")
        self.assertEqual(baz.unsuffixed_basename, "baz")
        
        baz2 = foo.add_child("baz$$")
        self.assertEqual(baz2.suffix, "")
        self.assertEqual(baz.unsuffixed_basename, "baz")

        self.assertCountEqual(
            list(foo.descendents()),
            [foo, bar, boing, baz, baz2]
        )        
    #enddef

    def test_entities(self):
        ent = "A test entity"

        ctx = Context("test")
        child = ctx.root.add_child("foo")
        child.entity = ent
        self.assertEqual(child.entity, ent)

        ent2 = [1, 2, 3]
        child.entity = ent2
        self.assertEqual(child.entity, ent2)
        ent2.append(10)
        self.assertEqual(child.entity, ent2)
        
    #enddef

    def test_mutation(self):
        ctx = Context("test")
        child = ctx.root.add_child("foo")
        grandchild = child.add_child("bar")
        another_child = ctx.root.add_child("ding")
        
        grandchild.basename = "dong"
        self.assertEqual(grandchild.basename, "dong")
        self.assertEqual(grandchild.fullname, "foo::dong")
        self.assertIn("dong", child.children)
        self.assertEqual(child.children["dong"], grandchild)

        grandchild.parent = another_child
        self.assertEqual(grandchild.parent, another_child)
        self.assertEqual(grandchild.fullname, "ding::dong")
        self.assertIn("dong", another_child.children)
        self.assertEqual(another_child.children["dong"], grandchild)

        with self.assertRaises(TypecheckExn):
            grandchild.parent = "bad parent"
        #endwith

        another_child.basename = "bang"
        self.assertEqual(grandchild.fullname, "bang::dong")
        
    #enddef

    def test_locate(self):
        ctx = Context("test")
        foo = ctx.root.add_child("foo")
        foo_ding = foo.add_child("ding")
        foo_gah = foo.add_child("gah")
        
        bar = ctx.root.add_child("bar")
        bar_ding = bar.add_child("ding")
        bar_ding_dong = bar_ding.add_child("dong")
        bar_boing = bar.add_child("boing")

        self.assertEqual(ctx.locate("foo::gah"), foo_gah)
        self.assertEqual(ctx.locate("bar::ding::dong"), bar_ding_dong)

        with self.assertRaises(NotFoundExn): ctx.locate("foo::dong")
        with self.assertRaises(NotFoundExn): ctx.locate("foo::boing")


        baz = ctx.root.add_child("baz")
        baz_ding = baz.add_child("ding")
        baz_dong_s1 = baz.add_child("dong$$s1")
        baz_dong_s2 = baz.add_child("dong$$s2")

        self.assertCountEqual(ctx.locate("baz::dong", gather_suffixes=True),
                              [baz_dong_s1, baz_dong_s2])

        self.assertCountEqual(ctx.locate("baz::dong$$xxx", gather_suffixes=True),
                              [baz_dong_s1, baz_dong_s2])

        self.assertCountEqual(ctx.locate("baz::ding", gather_suffixes=True),
                              [baz_ding])
        
        baz_ding_s1 = baz.add_child("ding$$s1")

        self.assertCountEqual(ctx.locate("baz::ding", gather_suffixes=True),
                              [baz_ding, baz_ding_s1])

        with self.assertRaises(NotFoundExn):
            ctx.locate("baz::doh", gather_suffixes=True)
        #endwith
        
    #enddef

    def test_build(self):
        ctx = Context("test")
        foo = ctx.root.add_child("foo")
        foo_ding = foo.add_child("ding")
        foo_gah = foo.add_child("gah")
        
        bar = ctx.root.add_child("bar")
        bar_ding = bar.add_child("ding")
        bar_ding_dong = bar_ding.add_child("dong")
        bar_boing = bar.add_child("boing")

        self.assertEqual(ctx.build("foo::gah"), foo_gah)

        foo_boing = ctx.build("foo::boing")
        self.assertCountEqual(
            foo.children.items(),
            [("ding", foo_ding),
             ("gah", foo_gah),
             ("boing", foo_boing)]
        )

        bazzy_baggy = ctx.build("bazzy::baggy")
        bazzy = bazzy_baggy.parent
        self.assertEqual(bazzy.basename, "bazzy")
        self.assertCountEqual(
            ctx.root.children.items(),
            [("foo", foo),
             ("bar", bar),
             ("bazzy", bazzy)]
        )

        self.assertCountEqual(
            bazzy.children.items(),
            [("baggy", bazzy_baggy)]
        )

    #enddef
    
    def test_search(self):

        ctx = Context("test")
        foo = ctx.root.add_child("foo")
        foo_ding = foo.add_child("ding")
        foo_gah = foo.add_child("gah")
        
        bar = ctx.root.add_child("bar")
        bar_ding = bar.add_child("ding")
        bar_ding_dong = bar_ding.add_child("dong")
        bar_ding_blah = bar_ding.add_child("blah")
        bar_ding_gah = bar_ding.add_child("gah")
        bar_boing = bar.add_child("boing")

        baz = ctx.root.add_child("baz")
        baz_ding = baz.add_child("ding")
        baz_ding_sleeh = baz_ding.add_child("sleeh")
               
        self.assertCountEqual(ctx.root.search("foo"), [])
        self.assertCountEqual(
            ctx.search("foo", only_terminal=False),
            [foo]
        )
        self.assertCountEqual(
            ctx.search("foo::"),
            [foo_ding, foo_gah]
        )

        self.assertCountEqual(
            ctx.search("bar:*:"),
            [bar_ding_dong, bar_ding_blah, bar_ding_gah, bar_boing]
        )
        
        self.assertCountEqual(
            ctx.search(":*:gah"),
            [foo_gah, bar_ding_gah]
        )

        self.assertCountEqual(
            ctx.search(":*:.*ah"),
            [foo_gah, bar_ding_blah, bar_ding_gah]
        )

        self.assertCountEqual(
            ctx.search("foo::.*g.*"),
            [foo_ding, foo_gah]
        )

        self.assertCountEqual(
            ctx.search(":*:ding::.l[A-Za-z]+h$"),
            [bar_ding_blah, baz_ding_sleeh]
        )
       
    #enddef

    def test_remove(self):
        ctx = Context("test")
        foo = ctx.root.add_child("foo")
        foo_ding = foo.add_child("ding")
        foo_gah = foo.add_child("gah")
        foo_ding_dong = foo_ding.add_child("dong")

        foo.remove_child("ding")

        self.assertCountEqual(
            foo.children.items(),
            [("gah", foo_gah)]
        )

        self.assertTrue(foo_ding.is_orphaned)
        with self.assertRaises(OrphanedExn): foo_ding.basename
        with self.assertRaises(OrphanedExn): foo_ding.parent
        with self.assertRaises(OrphanedExn): foo_ding.fullname
        with self.assertRaises(OrphanedExn): foo_ding.entity

        self.assertTrue(foo_ding_dong.is_orphaned)
        with self.assertRaises(OrphanedExn): foo_ding_dong.basename
        with self.assertRaises(OrphanedExn): foo_ding_dong.parent
        with self.assertRaises(OrphanedExn): foo_ding_dong.fullname
        with self.assertRaises(OrphanedExn): foo_ding_dong.entity
                
    #enddef

    def test_move(self):
        ctx = Context("test")
        foo = ctx.build("foo")
        foo_ding = ctx.build("foo::ding")
        bar = ctx.build("bar")
        bar_boing = ctx.build("bar::boing")
        bar_baz = ctx.build("bar::baz")

        ctx.move("foo::ding", "foo::dong")
        self.assertEqual(foo_ding.fullname, "foo::dong")
        self.assertIn("dong", foo.children)
        self.assertEqual(foo.children["dong"], foo_ding)

        ctx.move("foo::dong", "bar::boing::splat")
        
        self.assertEqual(foo_ding.fullname, "bar::boing::splat")
        self.assertIn("splat", bar_boing.children)
        self.assertEqual(bar_boing.children["splat"], foo_ding)

        with self.assertRaises(DuplicateNameExn):
            ctx.move("bar::boing::splat", "bar::baz")
        #endwith

        ctx.move("bar::boing::splat", "quux")
        self.assertEqual(foo_ding.fullname, "quux")
        self.assertIn("quux", ctx.root.children)
        self.assertEqual(ctx.root.children["quux"], foo_ding)


        ctx.move("bar", "foo::barrie")
        self.assertIn("barrie", foo.children)
        self.assertEqual(foo.children["barrie"], bar)
        self.assertEqual(bar_baz.fullname, "foo::barrie::baz")
        foo_barrie_baz = ctx.locate("foo::barrie::baz")
        self.assertEqual(foo_barrie_baz, bar_baz)
        
    #enddef

    def test_events(self):

        ctx = Context("test")
        foo = ctx.build("foo")
        foo_ding = ctx.build("foo::ding")
        bar = ctx.build("bar")
        bar_boing = ctx.build("bar::boing")
        bar_boing_baz = ctx.build("bar::boing::baz")
        bar_boing_quux = ctx.build("bar::boing::quux")

        baz = ctx.build("baz")
        baz_bing = ctx.build("baz::bing")
        baz_bong = ctx.build("baz::bong")
        baz_bang = ctx.build("baz::bang")
        
        manager = event.manager

        # Check add event
        @self.check_called
        def add_handler(ev):
            self.assertIsInstance(ev, AddChildEvent)
            self.assertEqual(ev.parent, foo)
            self.assertEqual(ev.childname, "dong")
        #enddef
        manager.reset()
        manager.register_handler(AddChildEvent, add_handler)
        foo.add_child("dong")
        self.wait_for_events()
        self.assertTrue(add_handler.was_called())

        # Check remove event and orphan event
        @self.check_called
        def remove_handler(ev):
            self.assertIsInstance(ev, RemoveChildEvent)
            self.assertEqual(ev.parent, foo)
            self.assertEqual(ev.childname, "ding")
            # Try to access the basename of the child that is to be
            # removed, to confirm it has not yet been orphaned.
            self.assertEqual(foo_ding.basename, "ding")
        #enddef
        @self.check_called
        def orphan_handler(ev):
            self.assertIsInstance(ev, OrphanEvent)
            self.assertEqual(ev.qname, foo_ding)
            # Try to access the basename of the child that is to be
            # removed, to confirm it has not yet been orphaned.
            self.assertEqual(foo_ding.basename, "ding")
        #enddef
        
        manager.reset()
        manager.register_handler(RemoveChildEvent, remove_handler)
        manager.register_handler(OrphanEvent, orphan_handler)
        foo.remove_child("ding")
        self.wait_for_events()
        self.assertTrue(remove_handler.was_called())
        self.assertTrue(orphan_handler.was_called())
        
        # Check cascading remove events in children
        removed_children = []
        orphans = []
        def remove_handler(ev):
            self.assertIsInstance(ev, RemoveChildEvent)
            removed_children.append((ev.parent, ev.childname))
        #enddef
        def orphan_handler(ev):
            self.assertIsInstance(ev, OrphanEvent)
            orphans.append(ev.qname.basename)
        #enddef
        manager.reset()
        manager.register_handler(RemoveChildEvent, remove_handler)
        manager.register_handler(OrphanEvent, orphan_handler)
        bar.remove_child("boing")
        self.wait_for_events()
        self.assertCountEqual(removed_children,
                              [(bar_boing, "baz"),
                               (bar_boing, "quux"),
                               (bar, "boing")])
        self.assertCountEqual(orphans,
                              ["baz", "quux", "boing"])

        # Check rename event.
        @self.check_called
        def rename_handler(ev):
            self.assertIsInstance(ev, RenameEvent)
            self.assertEqual(ev.qname, baz_bing)
            self.assertEqual(ev.old_name, "bing")
            self.assertEqual(ev.new_name, "splat")
        #enddef
        manager.reset()
        manager.register_handler(RenameEvent, rename_handler)
        baz_bing.basename = "splat"
        self.wait_for_events()
        self.assertTrue(rename_handler.was_called())

        # Check events for node adoption
        events = []
        def handler(ev):
            events.append(ev)
        #enddef
        manager.reset()
        manager.register_handler(QNameEvent, handler)
        baz_bong.parent = foo
        self.wait_for_events()
        self.maxDiff = None
        self.assertEventsMatch(
            events,
            ((ChildMoveEvent, (("origin", baz),
                               ("qname", baz_bong),
                               ("old_parent", baz),
                               ("new_parent", foo),
                               ("old_name", "bong"),
                               ("new_name", None))),
             (ChildMoveEvent, (("origin", foo),
                               ("qname", baz_bong),
                               ("old_parent", baz),
                               ("new_parent", foo),
                               ("old_name", "bong"),
                               ("new_name", None))),
            ), include_origin=True
        )

        # Check events for node move that is just a rename
        events = []
        @self.check_called
        def handler(ev):
            events.append(ev)
        #enddef
        manager.reset()
        manager.register_handler(QNameEvent, handler)
        ctx.move("baz::bang", "baz::quux")
        self.wait_for_events()
        self.assertTrue(handler.was_called())
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertIsInstance(ev, RenameEvent)
        self.assertEqual(ev.qname, baz_bang)
        self.assertEqual(ev.old_name, "bang")
        self.assertEqual(ev.new_name, "quux")
        
        # Check events for node move
        events = []
        @self.check_called
        def handler(ev): events.append(ev)
        manager.reset()
        manager.register_handler(QNameEvent, handler)
        baz_quux = baz_bang
        ctx.move("baz::quux", "foo::boing")
        self.wait_for_events()
        self.assertTrue(handler.was_called())

        self.assertEventsMatch(events, (
            (ChildMoveEvent, (("origin", baz),
                              ("qname", baz_quux),
                              ("old_parent", baz),
                              ("new_parent", foo),
                              ("old_name", "quux"),
                              ("new_name", "boing"))),
            (ChildMoveEvent, (("origin", foo),
                              ("qname", baz_quux),
                              ("old_parent", baz),
                              ("new_parent", foo),
                              ("old_name", "quux"),
                              ("new_name", "boing"))),
        ), include_origin=True)
       
    #enddef

    def test_emit_relay_events(self):
        # Event tests from the perspective of observers.

        manager = event.manager
        
        ctx = Context("test")
        foo = ctx.build("foo")
        foo_ding = ctx.build("foo::ding")
        foo_dong = ctx.build("foo::dong")
        foo_dong_doh = ctx.build("foo::dong::doh")
        bar = ctx.build("bar")
        bar_bleh = ctx.build("bar::bleh")
        bar_blah = ctx.build("bar::blah")

        def reset():
            manager.reset()
            for qn in ctx.root.descendents():
                qn.clear_all_event_observers()
            #endfofr
        #enddef
        
        # Test observers receiving events.
        events = []
        reset()
        foo.add_event_observer(events.append)
        foo_hee = foo.add_child("hee")
        self.wait_for_events()
        self.assertEqual(len(events), 1)
        self.assertIsInstance(events[0], AddChildEvent)
        self.assertEqual(events[0].parent, foo)
        self.assertEqual(events[0].childname, "hee")

        # Test parent and children bearings
        parent_events = []
        child_events = []
        reset()
        foo.add_relay_event_observer(lambda *args: parent_events.append(args))
        foo_dong_doh.clear_all_event_observers()
        foo_dong_doh.add_relay_event_observer(lambda *args: child_events.append(args))
        foo_dong_haa = foo_dong.add_child("haa")
        self.wait_for_events()

        self.assertEventsMatch(parent_events, (
            ((BRG_PARENT, AddChildEvent), (("parent", foo_dong),
                                           ("childname", "haa"))),
        ), includes_bearings=True)
        self.assertEventsMatch(child_events, (
            ((BRG_CHILDREN, AddChildEvent), (("parent", foo_dong),
                                             ("childname", "haa"))),
        ), includes_bearings=True)

        # Test relayed events for move.
        foo_events = []
        foo_dong_haa_events = []
        bar_blah_events = []
        reset()
        foo.add_relay_event_observer(lambda *args: foo_events.append(args))
        foo_dong_haa.add_relay_event_observer(lambda *args: foo_dong_haa_events.append(args))
        bar_blah.add_relay_event_observer(lambda *args: bar_blah_events.append(args))
        ctx.move("foo::dong", "bar::argh")
        self.wait_for_events()
        self.assertEventsMatch(foo_events, (
            ((event.BRG_ORIGIN, ChildMoveEvent), (("qname", foo_dong),
                                            ("old_parent", foo),
                                            ("new_parent", bar),
                                            ("old_name", "dong"),
                                            ("new_name", "argh"))),
        ), includes_bearings=True)
        self.assertEventsMatch(foo_dong_haa_events, (
            ((BRG_CHILDREN, ChildMoveEvent), (("qname", foo_dong),
                                              ("old_parent", foo),
                                              ("new_parent", bar),
                                              ("old_name", "dong"),
                                              ("new_name", "argh"))),
        ), includes_bearings=True)
        self.assertEventsMatch(bar_blah_events, (
            ((BRG_CHILDREN, ChildMoveEvent), (("qname", foo_dong),
                                              ("old_parent", foo),
                                              ("new_parent", bar),
                                              ("old_name", "dong"),
                                              ("new_name", "argh"))),
        ), includes_bearings=True)
       
    #enddef

    # XXX: TODO: Add tests for setting caused_by values in emitted events.
    # XXX: TODO: Add tests for is_clean event.
    
#endclass
