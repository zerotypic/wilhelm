#
# lazylist : Lazy list implementation
#

import itertools
from types import GeneratorType

from . import TYPECHECK, TypecheckExn

class LazyList(object):

    def __init__(self, backend):
        # Backend is treated as a generator producing items in the list.
        if type(backend) == GeneratorType:
            self._gen = backend
        else:
            self._gen = (x for x in backend)
        #endif
        # List items that have already been produced.
        self._accum = []
        # Whether the list is fully expanded, i.e. nothing is left in _gen.
        self._expanded = False
    #enddef

    def _force(self):
        '''Produce a new item from the backend generator.'''
        if self._expanded: raise StopIteration
        try:
            n = self._gen.__next__()
        except StopIteration as e:
            self._expanded = True
            raise(e)
        #endtry
        self._accum.append(n)
        #print("Forced, n = {}".format(n))
        return n
    #enddef

    def _forceto(self, i):
        '''Force items till the item at index i has been produced.'''
        while i >= len(self._accum): self._force()
        return self._accum[i]
    #enddef
    
    def _expand(self):
        '''Produce all possible items in the list.'''
        if self._expanded: return self
        try:
            while True: self._force()
        except StopIteration:
            return self
        #endtry
    #enddef                
    
    def __iter__(self):
        if self._expanded: return iter(self._accum)
        class Iterator(object):
            def __init__(self, nodelist):
                self.nodelist = nodelist
                self.nextcount = 0
                #print("Created iterator.")
            #enddef
            def __iter__(self): return self
            def __next__(self):
                #print("Calling iter.__next__")
                n = self.nodelist._forceto(self.nextcount)
                self.nextcount += 1
                #print("Got n = {}, nextcount is now {}".format(n, self.nextcount))
                return n
            #enddef
        #endclass
        return Iterator(self)
    #enddef

    def __len__(self):
        self._expand()
        return len(self._accum)
    #enddef

    def __add__(self, other):
        return self.__class__(itertools.chain(self, other))
    #enddef

    def __getitem__(self, key):
        if type(key) == int:
            try:
                return self._forceto(key)
            except StopIteration:
                raise IndexError("list index out of range")
            #endtry
        elif type(key) == slice:
            # XXX TODO: More efficient implementation
            self._expand()
            return self._accum[key]
        else:
            raise TypeError
        #endif
    #enddef

    def __contains__(self, item):
        return self._expand()._accum.__contains__(item)
    #enddef

    def __repr__(self):
        strs = [repr(n) for n in self._accum]
        if not self._expanded: strs.append("...")
        return "{}({})".format(self.__class__.__name__, ", ".join(strs))
    #enddef
    
#endclass

def MakeTypedLazyList(item_type):
    TYPECHECK(item_type, type)
    class TypedLazyList(LazyList):
        def _force(self):
            n = super(TypedLazyList, self)._force()
            TYPECHECK(n, item_type)
            return n
        #enddef
    #endclass
    TypedLazyList.__name__ = "TypedLazyList<{}>".format(item_type.__name__)
    return TypedLazyList
#enddef

#
# UNIT TESTS
#

import unittest

class Test(unittest.TestCase):

    def test_create_list(self):
        ll = LazyList([11, 22, 33])
        self.assertEqual([11, 22, 33], list(ll))
    #enddef

    def test_create_gen(self):
        ll = LazyList((x for x in [11, 22, 33]))
        self.assertEqual([11, 22, 33], list(ll))
    #enddef

    def test_create_fail(self):
        with self.assertRaises(TypeError): LazyList(10)
    #enddef

    def test_len(self):
        ll = LazyList((x for x in [11, 22, 33]))
        self.assertEqual(3, len(ll))

        ll = LazyList((x for x in [11, 22, 33]))
        next(iter(ll))
        self.assertEqual(3, len(ll))
    #enddef
    
    def test_index(self):
        ll = LazyList((x for x in [11, 22, 33]))
        self.assertEqual(11, ll[0])
        self.assertEqual(22, ll[1])
        self.assertEqual(33, ll[2])
        self.assertEqual(33, ll[-1])
        with self.assertRaises(IndexError): ll[10]
    #enddef

    def test_index_reverse(self):
        ll = LazyList((x for x in [11, 22, 33]))
        self.assertEqual(33, ll[2])
        self.assertEqual(22, ll[1])
        self.assertEqual(11, ll[0])
    #enddef

    def test_iterator(self):
        ll = LazyList((x for x in [11, 22, 33]))
        it = iter(ll)
        results = []
        for i in it: results.append(i)
        self.assertEqual([11, 22, 33], results)
    #enddef

    def test_iterator_end(self):
        ll = LazyList((x for x in [11, 22, 33]))
        it = iter(ll)
        next(it)
        next(it)
        next(it)
        with self.assertRaises(StopIteration): next(it)
    #enddef
    
    def test_iterator_multi(self):
        ll = LazyList((x for x in [11, 22, 33]))
        it1 = iter(ll)
        self.assertEqual(11, next(it1))
        it2 = iter(ll)
        self.assertEqual(11, next(it2))
        self.assertEqual(22, next(it2))
        self.assertEqual(33, next(it2))
        self.assertEqual(22, next(it1))
        self.assertEqual(33, next(it1))
    #enddef

    def test_iterator_index_mix(self):
        ll = LazyList((x for x in [11, 22, 33, 44]))
        it = iter(ll)
        self.assertEqual(11, next(it))
        self.assertEqual(11, ll[0])
        self.assertEqual(22, next(it))
        self.assertEqual(44, ll[3])
        self.assertEqual(33, next(it))
        self.assertEqual(44, next(it))
    #enddef

    def test_add(self):
        ll1 = LazyList((x for x in [11, 22, 33]))
        ll2 = LazyList((x for x in [44, 55, 66]))
        ll = ll1 + ll2
        self.assertEqual([11, 22, 33, 44, 55, 66],
                         list(ll))

        self.assertEqual([11, 22, 33], list(ll1))
        self.assertEqual([44, 55, 66], list(ll2))
        
        ll1 = LazyList((x for x in [11, 22, 33]))
        ll2 = LazyList((x for x in [44, 55, 66]))
        next(iter(ll1))
        ll2._expand()
        ll = ll1 + ll2
        self.assertEqual([11, 22, 33, 44, 55, 66],
                         list(ll))
    #enddef

    def test_contains(self):
        ll = LazyList((x for x in [11, 22, 33]))
        self.assertTrue(22 in ll)
        self.assertFalse(99 in ll)

        ll = LazyList((x for x in [11, 22, 33]))
        it = iter(ll)
        next(it)
        next(it)
        self.assertTrue(11 in ll)
        self.assertTrue(33 in ll)
    #enddef

    def test_slice(self):
        ll = LazyList((x for x in [11, 22, 33, 44, 55]))
        self.assertEqual([11, 22, 33], ll[:3])
        self.assertEqual([33, 44], ll[2:4])
        self.assertEqual([11, 33], ll[0:4:2])
        self.assertEqual([11, 22, 33, 44], ll[:-1])
        self.assertEqual([33, 44, 55], ll[-3:])

        ll = LazyList((x for x in [11, 22, 33, 44, 55]))
        it = iter(ll)
        next(it)
        next(it)
        self.assertEqual([11, 22, 33], ll[:3])
    #enddef

    def test_typed(self):

        IntLazyList = MakeTypedLazyList(int)

        ill = IntLazyList((x for x in [11, 22, 33]))
        self.assertEqual([11, 22, 33], list(ill))

        ill = IntLazyList((x for x in [11, "foo", 33]))
        with self.assertRaises(TypecheckExn): list(ill)
        
    #enddef
    
#endclass
