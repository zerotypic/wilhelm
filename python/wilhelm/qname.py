#
# qname : Qualified names for wilhelm
#

import itertools
import re

from . import event
from . import util
from .util import TYPECHECK, TypecheckExn
from .util.immutable import immdict

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
    def __init__(self, ctx, **kwargs):
        super().__init__(tag=ctx.name, **kwargs)
        self.ctx = ctx
    #enddef
#endclass

# This event gets triggered after the child is added.
class AddChildEvent(QNameEvent):
    def __init__(self, ctx, parent, childname, **kwargs):
        super().__init__(ctx, **kwargs)
        self.parent = parent
        self.childname = childname
    #enddef
#endclass

# This event gets triggered before the child is removed.
class RemoveChildEvent(QNameEvent):
    def __init__(self, ctx, parent, childname, **kwargs):
        super().__init__(ctx, **kwargs)
        self.parent = parent
        self.childname = childname
    #enddef
#endclass

# This event gets triggered before a qname is orphaned (deleted)
class OrphanEvent(QNameEvent):
    def __init__(self, ctx, qname, **kwargs):
        super().__init__(ctx, **kwargs)
        self.qname = qname
    #enddef
#endclass

# This event get triggered after a qname is renamed.
class RenameEvent(QNameEvent):
    def __init__(self, ctx, qname, old_name, new_name, **kwargs):
        super().__init__(ctx, **kwargs)
        self.qname = qname
        self.old_name = old_name
        self.new_name = new_name
    #enddef
#endclass

class ChangeParentEvent(QNameEvent):
    def __init__(self, ctx, qname, old_parent, new_parent, **kwargs):
        super().__init__(ctx, **kwargs)
        self.qname = qname
        self.old_parent = old_parent
        self.new_parent = new_parent
    #enddef
#endclass

# Bearings for qnames
BRG_PARENT = event.Bearing("qname.parent")
BRG_CHILDREN = event.Bearing("qname.children")

class Root(BRG_PARENT.Relay, BRG_CHILDREN.Relay):

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
    
    def add_child(self, child_basename):
        '''Creates and returns a new child to this namespace with basename 'child_basename'.'''
        self._check_duplicate_name(child_basename)
        new_child = QName(self._ctx, self, child_basename)
        self._add_child(new_child)
        self.emit_event(AddChildEvent, self._ctx, self, child_basename)
        return new_child           
    #enddef

    def remove_child(self, child_basename):
        '''Removes the child with basename 'child_basename' from this
        namespace. The child object becomes an orphaned QName and cannot
        be used.'''
        if child_basename in self._children:
            child = self._children[child_basename]
            self._orphan_child(child)
        else:
            raise NotFoundExn("Cannot find child '{}' to delete.".format(child_basename))
        #endif        
    #enddef

    def _orphan_child(self, child):
        # Wait for event handlers to finish before we remove the child, so
        # they can access the child before it gets orphaned.
        self.emit_event_and_wait(RemoveChildEvent, self._ctx, self, child._basename)

        children = list(child.children.values())
        for c in children: child._orphan_child(c)

        child.emit_event_and_wait(OrphanEvent, child._ctx, child)
        
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
    def _adopt_child(self, new_child, new_name=None):
        TYPECHECK(new_child, QName)
        if new_name == None:
            self._check_duplicate_name(new_child._basename)
        #endif
        new_child._ctx = self._ctx
        old_parent = new_child._parent
        # Wait for RemoveChild event handlers to complete before
        # continuing.
        old_parent.emit_event_and_wait(RemoveChildEvent, old_parent._ctx,
                                       old_parent, new_child._basename)
        old_parent._remove_child(new_child)
        rename_event_info = None
        if new_name != None and new_name != new_child._basename:
            self._check_duplicate_name(new_name)
            # We delay sending the rename event till after the child has
            # been properly adopted, to prevent event handlers from seeing
            # a transient state.
            rename_event_info = (new_child._basename, new_name)
            new_child._basename = new_name
        #endif
        new_child._parent = self
        self._add_child(new_child)
        if rename_event_info != None:
            # We can send the rename event now as the child has been
            # properly adopted, with a new name.
            (old_name, new_name) = rename_event_info
            new_child.emit_event(RenameEvent, new_child._ctx, new_child, old_name, new_name)
        #endif
        new_child.emit_event(ChangeParentEvent, new_child._ctx, new_child, old_parent, self)
        self.emit_event(AddChildEvent, self._ctx, self, new_child._basename)
        return new_child
    #enddef

    def _rename_child(self, old_name, new_name):
        self._check_duplicate_name(new_name)
        if not old_name in self._children:
            raise NotFoundExn("Cannot find child '{}' to rename.".format(old_name))
        #endif
        child = self._children[old_name]
        self._remove_child(child)
        child._basename = new_name
        self._add_child(child)
        child.emit_event(RenameEvent, child._ctx, child, old_name, new_name)
    #enddef
    
    def clear(self):
        children = list(self._children.values())
        for c in children: self._orphan_child(c)
    #enddef
    
    def search(self, query, **kwargs):
        return list(itertools.chain(*(child.search(query, **kwargs) for child in self._children.values())))
    #enddef

#endclass

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
    def basename(self, value): self._parent._rename_child(self._basename, value)
    
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
    def parent(self, new_parent):
        TYPECHECK(new_parent, Root)
        if new_parent._ctx != self._ctx:
            print("WARNING: Changing to a parent with a different context!")
        #endif
        new_parent._adopt_child(self)
    #enddef
    
    @property
    def fullname(self): return self._parent._join(self.basename)

    @property
    def entity(self): return self._entity

    @entity.setter
    def entity(self, value): self._entity = value   

    @property
    def is_terminal(self): return len(self._children) == 0
    
    @property
    def is_orphaned(self): return self._parent == None

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
    #enddef

    def __repr__(self): return "Context<%s>" % self.name
    
    @property
    def name(self): return self._name
    
    @property
    def root(self): return self._root

    def _locate(self, qns, build=False):

        namelist = qns_split(qns)
        
        cur = self.root
        found = False
        for match_name in namelist:
            if not match_name in cur.children:
                if build:
                    cur = cur.add_child(match_name)
                else:
                    #print("Could not find sub-name %s." % match_name)
                    return None
                #endif
            else:
                cur = cur.children[match_name]
            #endif
        #endwhile

        return cur
        
    #enddef

    def locate(self, qns, build=False):
        qn = self._locate(qns, build=build)
        if qn == None:
            raise NotFoundExn("Could not find name {}".format(qns))
        #endif
        return qn
    #enddef
    
    def contains(self, qns):
        qn = self._locate(qns)
        return qn != None
    #enddef
    
    def build(self, qns):
        return self._locate(qns, build=True)
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

        To match qnames with arbitrary parent identifiers, start the query with ":*". 
        For example, ":*:foo" matches "this::is::foo", "also::foo" and "foo".
        '''
        return self.root.search(query, **kwargs)
    #enddef    

    def move(self, old_qns, new_qns):
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
            qn.parent._rename_child(qn.basename, new_basename)
        else:
            new_parent._adopt_child(qn, new_name=new_basename)
        #endif

    #enddef
    
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

    def assertEventsMatch(self, events, specs, includes_bearings=False):
        # specs should be a list of 'spec' objects, where a spec is of the
        # form: (<event type>, <property list>),
        # or ((<bearing>, <event type>), <property list>) if
        # includes_bearings is True.
        # <property list> is a list of 2-tuples (<name>, <value>) where
        # <name> is the name of an event property, and <value> is the
        # expected value of that property.
        # We ignore the "ctx" property, so that does not need to be
        # included in the spec list.

        # To perform the match, we sort the event list and the spec list.

        def get_event_properties(ev):
            return [(k, v) for (k, v) in ev.__dict__.items()
                    if not k.startswith("_") and not k == "ctx"]
        #enddef

        if includes_bearings:
            def event_info(bev): return ((bev[0], type(bev[1])), get_event_properties(bev[1]))
            def event_sort_key(bev):
                ((bearing, evtype), props) = event_info(bev)
                return (bearing, repr(evtype), props)
            #enddef
            def spec_sort_key(spec):
                ((bearing, event), props) = spec
                return ((bearing, repr(event)), props)
            #enddef
        else:
            def event_info(ev): return (type(ev), get_event_properties(ev))
            def event_sort_key(ev):
                (evtype, props) = event_info(ev)
                return (repr(evtype), props)
            #enddef
            def spec_sort_key(spec):
                (event, props) = spec
                return (repr(event), props)
            #enddef
        #endif

        sorted_events = sorted(events, key=event_sort_key)
        sorted_specs = sorted(specs, key=spec_sort_key)

        if len(sorted_events) != len(sorted_specs):
            self.fail("Event list does not match spec:\nEvents:\t{}\nSpecs:\t{}".format(
                sorted_events, sorted_specs))
        #endif
                
        for (i, ev) in enumerate(sorted_events):
            (ev_type, ev_props) = event_info(ev)
            (spec_type, spec_props) = sorted_specs[i]

            self.assertEqual(ev_type, spec_type)
            self.assertCountEqual(ev_props, spec_props)
            
        #endfor

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
        #enddef
        @self.check_called
        def orphan_handler(ev):
            self.assertIsInstance(ev, OrphanEvent)
            self.assertEqual(ev.qname, foo_ding)
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
        @self.check_called
        def remove_handler(ev):
            self.assertIsInstance(ev, RemoveChildEvent)
            removed_children.append((ev.parent, ev.childname))
        #enddef
        manager.reset()
        manager.register_handler(RemoveChildEvent, remove_handler)
        bar.remove_child("boing")
        self.wait_for_events()
        self.assertCountEqual(removed_children,
                              [(bar_boing, "baz"),
                               (bar_boing, "quux"),
                               (bar, "boing")])

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
        @self.check_called
        def handler(ev):
            events.append(ev)
        #enddef
        manager.reset()
        manager.register_handler(QNameEvent, handler)
        baz_bong.parent = foo
        self.wait_for_events()
        self.assertTrue(handler.was_called())
        self.maxDiff = None
        self.assertEventsMatch(
            events,
            ((RemoveChildEvent, (("parent", baz),
                                 ("childname", "bong"))),
             (AddChildEvent, (("parent", foo),
                              ("childname", "bong"))),
             (ChangeParentEvent, (("qname", baz_bong),
                                  ("old_parent", baz),
                                  ("new_parent", foo))),
            )
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
            (RemoveChildEvent, (("parent", baz),
                                ("childname", "quux"))),
            (RenameEvent, (("qname", baz_quux),
                           ("old_name", "quux"),
                           ("new_name", "boing"))),
            (AddChildEvent, (("parent", foo),
                             ("childname", "boing"))),
            (ChangeParentEvent, (("qname", baz_quux),
                                 ("old_parent", baz),
                                 ("new_parent", foo))),
        ))
        
        # XXX: STOPPED HERE
        # Change the code below to use self.assertEventsMatch(), and cater
        # for new ChangeParentEvent's.

        # self.assertEqual(len(events), 2)
        # (rm_ev, add_ev) = events
        # self.assertIsInstance(rm_ev, RemoveChildEvent)
        # self.assertEqual(rm_ev.parent, baz)
        # self.assertEqual(rm_ev.childname, "quux")
        # self.assertIsInstance(add_ev, AddChildEvent)
        # self.assertEqual(add_ev.parent, foo)
        # self.assertEqual(add_ev.childname, "boing")

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
        events = []
        reset()
        foo_dong_haa.add_relay_event_observer(lambda *args: events.append(args))
        ctx.move("foo::dong", "bar::argh")
        self.wait_for_events()
        self.assertEventsMatch(events, (
            ((BRG_CHILDREN, RemoveChildEvent), (("parent", foo),
                                                ("childname", "dong"))),
            ((BRG_CHILDREN, RenameEvent), (("qname", foo_dong),
                                           ("old_name", "dong"),
                                           ("new_name", "argh"))),
            ((BRG_CHILDREN, AddChildEvent), (("parent", bar),
                                             ("childname", "argh"))),
            ((BRG_CHILDREN, ChangeParentEvent), (("qname", foo_dong),
                                                 ("old_parent", foo),
                                                 ("new_parent", bar))),
        ), includes_bearings=True)
       
    #enddef
    
#endclass
