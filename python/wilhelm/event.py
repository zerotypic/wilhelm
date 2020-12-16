#
# event : Event management
#

import asyncio
import logging
import enum
import operator

from . import util
from .util import TYPECHECK
from .util import asyncutils

class Exn(Exception): pass
class UnknownHandlerExn(Exn): pass
class InvalidHandlerExn(Exn): pass
class LoopStartedExn(Exn): pass
class LoopNotStartedExn(Exn): pass
class InvalidObserverExn(Exn): pass
class UnknownObserverExn(Exn): pass
class InvalidBearingExn(Exn): pass
class InvalidRelayExn(Exn): pass

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = util.setup_logger(__name__)

PRIORITY_MIN = 0
PRIORITY_PRIV_MIN = -255

# Base class for special exceptions raised within event handlers.
class EventHandlerExn(Exception) : pass

# Special exception that allows a privileged (negative priority level)
# handler to run some code at the end of event handling.
class _PrivilegedHandlerPostActionExn(EventHandlerExn):
    def __init__(self, post_handler):
        self.post_handler = post_handler
    #enddef
#endclass

class Event(object):

    def __init__(self, origin=None, tag=None):
        if origin != None: TYPECHECK(origin, Emitter)
        self.__handled = asyncio.Event()
        self.__origin = origin
        self.__tag = None if tag == None else str(tag)
        self.__exns = None
    #enddef

    @property
    def tag(self): return self.__tag

    @property
    def origin(self): return self.__origin
    
    def is_handled(self): return self.__handled.is_set()

    def mark_handled(self, exns=None):
        if exns == []: exns = None
        self.__exns = exns
        self.__handled.set()
    #enddef

    def clear_handled(self): self.__handled.clear()

    def has_exceptions(self): return self.__exns != None
    
    def get_exceptions(self):
        '''Retrieve any exceptions raised by event handlers while this event was
        being processed. Returns a list of 2-tuples of the form (h, exn)
        where 'h' is the handler that raised exception 'exn'.
        '''
        return list(self.__exns) if self.__exns != None else []
    #enddef
    
    async def wait_till_handled(self): await self.__handled.wait()

#endclass

class Emitter(object):
    '''Base class for objects that can emit events.'''

    def __init__(self):
        self.__event_observers = []
    #enddef

    def add_event_observer(self, observer):
        if not callable(observer):
            raise InvalidObserverExn("Observer {!r} is not callable.".format(observer))
        #endif
        if not observer in self.__event_observers:
            self.__event_observers.append(observer)
        #endif
    #enddef

    def remove_event_observer(self, observer):
        if observer in self.__event_observers:
            self.__event_observers.remove(observer)
        else:
            raise UnknownObserverExn(
                "No observer {!r} for emitter {!r}".format(observer, self))
        #endif
    #enddef

    def clear_event_observers(self):
        self.__event_observers.clear()
    #enddef

    def clear_all_event_observers(self):
        self.clear_event_observers()
    #enddef
    
    def emit_event(self, evtype, *args, **kwargs):
        ev = evtype(*args, origin=self, **kwargs)
        manager.trigger(ev)
        return ev
    #enddef

    # Wait for event to be handled before continuing.
    def emit_event_and_wait(self, evtype, *args, **kwargs):
        ev = self.emit_event(evtype, *args, **kwargs)
        asyncutils.run_task_till_done(ev.wait_till_handled())
        return ev
    #enddef
    
    def _notify_observers(self, ev):
        for obs in self.__event_observers:
            obs(ev)
        #endfor
    #enddef
    
#endclass

class _RelayAdjacentsProperty(property):
    def __init__(self, bearing, *args, **kwargs):
        TYPECHECK(bearing, Bearing)
        DBG("RAP init: %r", (self, bearing, args, kwargs))
        super().__init__(*args, **kwargs)
        DBG("RAP super init called.")
        self._event_bearing = bearing
        DBG("RAP event_bearing set, exiting.")
    #enddef
    def setter(self, fset):
        return self.__class__(self._event_bearing, fget=self.fget, fset=fset, fdel=self.fdel)
    #enddef
    def deleter(self, fdel):
        return self.__class__(self._event_bearing, fget=self.fget, fset=self.fset, fdel=fdel)
    #enddef
#endclass

class RelayMeta(type):
    def __new__(cls, name, bases, dct):       
        #DBG("New Relay class being created: {!r}".format((cls, name, bases, dct)))
        info = {}
        # Add any info from base classes
        for b in bases:
            if type(b) == cls:
                info.update(b._event_relay_info)
            #endif
        #endfor
        # Search for adjacent properties, add to info dict, and replace with a
        # regular property.
        for (k, v) in list(dct.items()):
            if isinstance(v, _RelayAdjacentsProperty):
                DBG("Found _RelayAdjacentsProperty object: %r", v)
                DBG("\tevent_bearing = %r", v._event_bearing)
                bearing = v._event_bearing
                TYPECHECK(bearing, Bearing)
                new_v = property(fget=v.fget, fset=v.fset, fdel=v.fdel)
                dct[k] = new_v
                info[bearing] = new_v
            #endif
        #endfor
        dct["_event_relay_info"] = info
        return super(RelayMeta, cls).__new__(cls, name, bases, dct)
    #enddef
#endclass

RELAY = enum.Enum("RELAY", ("CONTINUE", "STOP"))
class _RelayStopExn(Exception): pass

class Relay(Emitter, metaclass=RelayMeta):

    def __init__(self):
        super().__init__()
        self.__relay_event_observers = []
    #enddef

    def add_relay_event_observer(self, observer):
        if not callable(observer):
            raise InvalidObserverExn("Relay observer {!r} is not callable.".format(observer))
        #endif
        if not observer in self.__relay_event_observers:
            self.__relay_event_observers.append(observer)
        #endif
    #enddef

    def remove_relay_event_observer(self, observer):
        if observer in self.__relay_event_observers:
            self.__relay_event_observers.remove(observer)
        else:
            raise UnknownObserverExn(
                "No relay observer {!r} for emitter {!r}".format(observer, self))
        #endif
    #enddef

    def clear_relay_event_observers(self):
        self.__relay_event_observers.clear()
    #enddef

    def clear_all_event_observers(self):
        self.clear_event_observers()
        self.clear_relay_event_observers()
    #enddef
    
    def _notify_relay_observers(self, bearing, ev):
        DBG("%r is notifying relay observers: %r", self, self.__relay_event_observers)
        if bearing != BRG_ORIGIN: TYPECHECK(self, bearing.Relay)
        for obs in self.__relay_event_observers:
            result = obs(bearing, ev)
            if result == RELAY.STOP: raise _RelayStopExn()
        #endfor
    #enddef

    def _relay_event(self, bearing, ev):

        if bearing == BRG_ORIGIN: return

        info = self.__class__._event_relay_info

        if not isinstance(self, bearing.Relay):
            raise InvalidBearingExn(
                "Relay {!r} is not on bearing {!r}".format(
                    self, bearing))
        #endif
        
        if not bearing in info:
            raise InvalidRelayExn(
                "Relay {!r} does not have an adjacents property for bearing {!r}".format(
                    self, bearing))
        #endif

        adjacents = info[bearing].fget(self)
        if isinstance(adjacents, Relay):
            # Singleton adjacent
            adjacents = [adjacents]
        elif adjacents == None:
            adjacents = []
        #endif
        DBG("Relaying event %r on bearing %r to adjacents: %r",
            ev, bearing, list(adjacents))
        for r in adjacents:
            r._notify_relay_observers(bearing, ev)
            r._relay_event(bearing, ev)
        #endfor

    #enddef

    @classmethod
    def _event_bearings(cls):
        return list(cls._event_relay_info.keys())
    #enddef
    
#endclass

class Bearing(object):
    def __init__(self, name):
        class _Relay(Relay):
            @self.adjacents_property
            def __missing_adjacents(self):
                raise TypeError("Relay adjacent property not defined for node.")
            #enddef
        #endclass
        _Relay.__qualname__ = "{}_Relay".format(name)
        _Relay.__name__ = _Relay.__qualname__
        self._name = name
        self.Relay = _Relay
    #enddef
    def __repr__(self): return "Bearing<{}>".format(self._name)
    
    def adjacents_property(self, func):
        DBG("Creating adjacents property, self = %r, func = %r", self, func)
        return _RelayAdjacentsProperty(self, fget=func)
    #enddef
#endclass

# The special origin bearing; events will always be relayed to the origin,
# allowing relay observers to see events emitted by the origin as well.
BRG_ORIGIN = Bearing("ORIGIN")

class EventManager(object):

    def __init__(self):
        self._q = asyncio.Queue()    # Event queue
        self.reset_handlers()
        self._loop_task = None
        self._last_exn_event = None
    #enddef

    def reset(self):
        self.reset_handlers()
        self._last_exn_event = None
        while self._q.qsize() > 0:
            self._q.get_nowait()
            self._q.task_done()
        #enddef
    #enddef
    
    def reset_handlers(self):
        self._handler_map = dict()
        self.register_handler(Event, self._default_handler, priority=99)
    #enddef

    # wilhelm-internal functions can call this to set negative (privileged) priorities
    def _register_handler(self, evtype, handler, tag=None, priority=0):
        if not callable(handler):
            raise InvalidHandlerExn("Handler {!r} is not callable.".format(handler))
        #endif
        if not evtype in self._handler_map: self._handler_map[evtype] = {}
        evmap = self._handler_map[evtype]
        if not tag in evmap: evmap[tag] = []
        priority = max(priority, PRIORITY_PRIV_MIN)
        evmap[tag].append((priority, handler))
    #enddef

    def register_handler(self, evtype, handler, tag=None, priority=0):
        if priority < PRIORITY_MIN: priority = PRIORITY_MIN
        return self._register_handler(evtype, handler, tag=tag, priority=priority)
    #enddef
    
    def unregister_handler(self, evtype, handler, tag=None):
        if not evtype in self._handler_map \
           or not tag in self._handler_map[evtype]:
            raise UnknownHandlerExn(
                "No handler {!r} for event type {!r}[{!r}]".format(handler, evtype, tag))
        #endif
        for (i, (_, f)) in enumerate(self._handler_map[evtype][tag]):
            if f == handler:
                self._handler_map[evtype][tag].pop(i)
                if len(self._handler_map[evtype][tag]) == 0:
                    del self._handler_map[evtype][tag]
                #endif
                if len(self._handler_map[evtype]) == 0:
                    del self._handler_map[evtype]
                #endif
                return
            #endif
        #endfor
        raise UnknownHandlerExn(
            "No handler {!r} for event type {!r}[{!r}]".format(handler, evtype, tag))
    #enddef

    # Decorator for writing handlers.
    def register(self, evtype):
        def _register(func):
            self.register_handler(evtype, func)
            return func
        #enddef
        return _register
    #enddef

    # Default event handler. This handler takes care of notifying
    # observers of the event's origin.
    def _default_handler(self, ev):
        # Notify observers of event's origin
        origin = ev.origin
        if isinstance(origin, Emitter):
            origin._notify_observers(ev)
        #endif
        
        # If origin is a relay, relay event.
        if isinstance(origin, Relay):

            DBG("Relaying events from relay %r", origin)
            # We always notify relay observers on the origin as well.
            DBG("Relaying to origin.")
            origin._notify_relay_observers(BRG_ORIGIN, ev)

            for b in origin._event_bearings():
                DBG("Relaying across bearing %r", b)
                try:
                    origin._relay_event(b, ev)
                except _RelayStopExn:
                    DBG("Relaying stopped as requested by observer.")
                    pass
                #endtry
            #endfor

        #endif
        
    #enddef
    
    async def trigger_async(self, ev):
        '''
        Triggers an event. Returns an asyncio.Event that is set when this
        event has been handled.
        '''
        TYPECHECK(ev, Event)
        DBG("Triggering event: %r", ev)
        await self._q.put(ev)
        DBG("Done triggering event: %r", ev)
        return ev
    #enddef

    def trigger(self, ev):
        DBG("Called event.manager.trigger on event %r", ev)
        t = asyncutils.run_task_till_done(self.trigger_async(ev))
        return t.result()
    #enddef

    def trigger_and_wait(self, ev):
        ev = self.trigger(ev)
        asyncutils.run_task_till_done(ev.wait_till_handled())
        return ev
    #enddef    

    async def wait_till_queue_empty(self):
        '''Waits till the event queue is empty.'''
        await self._q.join()
    #enddef
    
    def last_exn_event(self): return self._last_exn_event
    
    async def _event_loop(self):
        while True:
            DBG("Waiting for event queue")
            ev = await self._q.get()
            evtype = type(ev)
            DBG("Handling event %r", ev)
            
            handlers = []
            while True:

                # Because we have a default handler for the Event base class,
                # this loop will always be able to find a handler.           
                while not evtype in self._handler_map:
                    evtype = evtype.__bases__[0]
                #endwhile

                evmap = self._handler_map[evtype]

                # Default handlers for this type
                if None in evmap: handlers += evmap[None]
                
                # Tag-specific handlers for this type
                if ev.tag != None and ev.tag in evmap:
                    handlers += evmap[ev.tag]
                #endif

                # Break out of the loop when we hit the base event.
                if evtype == Event: break

                # Go up one supertype and find handlers for that.
                evtype = evtype.__bases__[0]
                
            #endwhile

            # Sort based on priority
            handlers.sort(key=operator.itemgetter(0))
            
            # Call all associated handlers.
            exns = []
            post_handlers = []
            DBG("Calling event handlers.")
            for (p, f) in handlers:
                try:
                    f(ev)
                except _PrivilegedHandlerPostActionExn as exn:
                    if p < PRIORITY_MIN:
                        post_handlers.append(exn.post_handler)
                    else:
                        WARNING("Non-privileged handler tried to set a post-handler, ignoring.")
                    #endif
                except Exception as exn:
                    exns.append((f, exn))
                #endtry
            #endfor
            DBG("Finished calling all event handlers.")

            if len(post_handlers) > 0:
                DBG("Post handlers have been registered, calling them now.")
                for ph in post_handlers:
                    try:
                        ph(ev)
                    except Exception as exn:
                        exns.append((ph, exn))
                    #endtry
                #endfor
                DBG("Finished calling post handlers.")
            #endif
                    
            if len(exns) == 0: exns = None
                
            # Mark that this event has been handled.
            ev.mark_handled(exns=exns)
            
            if exns != None:
                # This event has exceptions, store in _last_exn_event for
                # diagnostic purposes.
                if LOG.isEnabledFor(logging.DEBUG):
                    DBG("Event raised exceptions, recording.")
                    DBG("Exceptions:")
                    for exn in exns: DBG("\t %r", exn)
                #endif
                self._last_exn_event = ev
            #endif
            
            # XXX: Document somewhere that any exceptions raised by event
            # handlers end up stored in the event, and that if nothing
            # processes them they'll just disappear.
            # Maybe add some warning messages somewhere to note that
            # exceptions were raised, or have some mechanism where events
            # are explicitly closed, and if there are pending exceptions,
            # raise them.
            
            # Tell queue that we're done with this event.
            DBG("Inform queue that we're done with this event.")
            self._q.task_done()
            
        #endwhile
    #enddef

    def is_loop_started(self): return self._loop_task != None and not self._loop_task.done()
    
    def start_loop(self):
        if not self.is_loop_started():
            self._loop_task = asyncio.get_event_loop().create_task(self._event_loop())
        else:
            raise LoopStartedExn("Event loop already started.")
        #endif
        DBG("Event loop started.")
    #enddef

    def stop_loop(self):
        if self.is_loop_started():
            self._loop_task.cancel()
            self._loop_task = None
        else:
            raise LoopNotStartedExn("Event loop not started yet, cannot stop.")
        #endif
        DBG("Event loop stopped.")
    #enddef

    def __del__(self):
        DBG("event.manager.del called.")
        self.stop_loop()
    #enddef
    
#endclass

# The singleton event manager.
manager = EventManager()

manager.start_loop()

import atexit
@atexit.register
def cleanup():
    manager.stop_loop()
#enddef


#
# UNIT TESTS
#

import unittest
import contextlib

# TestCase class with additional functions to aid in testing events.
class EventTestCase(unittest.TestCase):

    def setUp(self):
        if not manager.is_loop_started(): manager.start_loop()
    #enddef

    def tearDown(self):
        if manager.is_loop_started(): manager.stop_loop()
    #enddef
   
    def check_called(self, func):
        func._was_called = asyncio.Event()
        def _func(*args, **kwargs):
            func._was_called.set()
            func(*args, **kwargs)
        #enddef
        _func.was_called = lambda: func._was_called.is_set()
        _func.clear_called = lambda: func._was_called.clear()
        return _func
    #enddef

    def run_coro(self, coro):
        t = asyncutils.run_task_till_done(coro)
        return t.result()
    #enddef

    def wait_for_events(self, ignore_exceptions=False):
        self.run_coro(manager._q.join())
        if not ignore_exceptions: self.raise_event_exn()
    #enddef

    def raise_event_exn(self):
        # Raises exception found in the last event that raised
        # exceptions.
        ev = manager.last_exn_event()
        if ev == None: return
        (_, exn) = ev.get_exceptions()[0]
        raise exn
    #enddef

    # Safe version of assertRaises() that doesn't clear the returned
    # exception, which would cause problems with the event loop.
    @contextlib.contextmanager
    def safeAssertRaises(self, exntype):
        try:
            yield None
        except exntype as e:
            return
        #endtry
        self.fail(msg="Expected {!r} exception.".format(exntype))
    #enddef
    
#endclass

class Test(EventTestCase):

    class SimpleEvent(Event):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
        #enddef
    #endclass
    
    class FooEvent(Event):
        def __init__(self, foo, **kwargs):
            self.foo = foo
            super().__init__(**kwargs)
        #enddef
        def __repr__(self): return "FooEvent<{}>".format(self.foo)
    #endclass

    class BarEvent(Event):
        def __init__(self, bar, **kwargs):
            self.bar = bar
            super().__init__(**kwargs)
        #enddef
        def __repr__(self): return "BarEvent<{}>".format(self.bar)
    #endclass
    
    class SpecialFooEvent(FooEvent): pass

    async def assertHandlerCalled(self, ev, handler, invert=False):
        handler.clear_called()
        ev.clear_handled()
        await manager.trigger_async(ev)
        await ev.wait_till_handled()
        if len(ev.get_exceptions()) > 0:
            raise ev.get_exceptions()[0]
        #endif
        if invert:
            self.assertFalse(handler.was_called())
        else:
            self.assertTrue(handler.was_called())
        #endif
    #enddef
    
    def test_basic(self):

        foo_event = Test.FooEvent("test")
        
        @self.check_called
        def foo_handler(ev):
            self.assertEqual(ev, foo_event)
            self.assertEqual(ev.foo, "test")
        #enddef

        manager.reset()
        manager.register_handler(Test.FooEvent, foo_handler)

        self.run_coro(self.assertHandlerCalled(foo_event, foo_handler))
        
        manager.unregister_handler(Test.FooEvent, foo_handler)

        self.run_coro(self.assertHandlerCalled(foo_event, foo_handler, invert=True))

        manager.register_handler(Test.FooEvent, foo_handler)
        manager.reset()
        
        self.run_coro(self.assertHandlerCalled(foo_event, foo_handler, invert=True))

        manager.reset()
        manager.register_handler(Test.FooEvent, foo_handler)

        bar_event = Test.BarEvent("bar")
        self.run_coro(self.assertHandlerCalled(bar_event, foo_handler, invert=True))
        
    #enddef

    def test_multi(self):

        bar_event = Test.BarEvent("bar")
        
        @self.check_called
        def bar_handler_a(ev): pass

        @self.check_called
        def bar_handler_b(ev): pass

        manager.reset()
        manager.register_handler(Test.BarEvent, bar_handler_a)
        manager.register_handler(Test.BarEvent, bar_handler_b)

        async def _check_multi():
            bar_handler_a.clear_called()
            bar_handler_b.clear_called()
            bar_event.clear_handled()
            await manager.trigger_async(bar_event)
            await bar_event.wait_till_handled()
            self.assertTrue(bar_handler_a.was_called())
            self.assertTrue(bar_handler_b.was_called())
        #enddef
        self.run_coro(_check_multi())
        
    #enddef
    
    def test_inherit(self):
        
        sfoo_event = Test.SpecialFooEvent("fooey")

        @self.check_called
        def foo_handler(ev):
            self.assertEqual(ev, sfoo_event)
            self.assertEqual(type(ev), Test.SpecialFooEvent)
            self.assertEqual(ev.foo, "fooey")
        #enddef
        
        manager.reset()
        manager.register_handler(Test.FooEvent, foo_handler)

        self.run_coro(self.assertHandlerCalled(sfoo_event, foo_handler))

        @self.check_called
        def sfoo_handler(ev):
            self.assertEqual(ev, sfoo_event)
            self.assertEqual(type(ev), Test.SpecialFooEvent)
            self.assertEqual(ev.foo, "fooey")
        #enddef
        manager.register_handler(Test.SpecialFooEvent, sfoo_handler)

        self.run_coro(self.assertHandlerCalled(sfoo_event, sfoo_handler))
        self.run_coro(self.assertHandlerCalled(sfoo_event, foo_handler))
        
    #enddef

    def test_exns(self):

        class TestExn(Exception): pass
        class AnotherTestExn(Exception): pass
        
        def handler1(ev):
            raise TestExn("test")
        #enddef
        def handler2(ev):
            raise AnotherTestExn("test")
        #enddef

        manager.reset()
        manager.register_handler(Test.FooEvent, handler1)
        manager.register_handler(Test.FooEvent, handler2)
        
        async def _test_exns():
            ev = Test.FooEvent("foo")
            await manager.trigger_async(ev)
            await ev.wait_till_handled()
            return (ev, ev.get_exceptions())
        #enddef
        t = asyncutils.run_task_till_done(_test_exns())

        (ev, exns) = t.result()
        
        self.assertEqual(len(exns), 2)

        (h, exn) = exns[0]
        self.assertEqual(h, handler1)
        self.assertEqual(type(exn), TestExn)
        
        (h, exn) = exns[1]
        self.assertEqual(h, handler2)
        self.assertEqual(type(exn), AnotherTestExn)

        self.assertEqual(manager.last_exn_event(), ev)
        
    #enddef

    def test_tags(self):

        tagged_bar_event = Test.BarEvent("bar", tag="fooey")
        
        @self.check_called
        def bar_handler_default(ev): pass

        @self.check_called
        def bar_handler_tagged_a(ev): pass

        @self.check_called
        def bar_handler_tagged_b(ev): pass

        manager.reset()
        manager.register_handler(Test.BarEvent, bar_handler_default)
        manager.register_handler(Test.BarEvent, bar_handler_tagged_a, tag="fooey")
        manager.register_handler(Test.BarEvent, bar_handler_tagged_b, tag="barry")

        async def _check_tagged():
            bar_handler_default.clear_called()
            bar_handler_tagged_a.clear_called()
            bar_handler_tagged_b.clear_called()
            tagged_bar_event.clear_handled()
            await manager.trigger_async(tagged_bar_event)
            await tagged_bar_event.wait_till_handled()
            self.assertTrue(bar_handler_tagged_a.was_called())
            self.assertFalse(bar_handler_tagged_b.was_called())
        #enddef
        self.run_coro(_check_tagged())
        
        manager.unregister_handler(Test.BarEvent, bar_handler_tagged_a, tag="fooey")
        self.run_coro(self.assertHandlerCalled(tagged_bar_event, bar_handler_tagged_a, invert=True))
        self.run_coro(self.assertHandlerCalled(tagged_bar_event, bar_handler_default))
        
    #enddef
   
    def test_priorities(self):

        results = []
        def first_handler(ev): results.append("first")
        def second_handler(ev): results.append("second")
        
        manager.reset()
        manager.register_handler(Test.FooEvent, first_handler, priority=10)
        manager.register_handler(Test.FooEvent, second_handler, priority=20)

        ev = Test.FooEvent("foo")
        manager.trigger(ev)
        self.wait_for_events()
        self.assertEqual(results, ["first", "second"])

        # Check that privileged priorities work.
        results = []
        manager.reset()
        manager.register_handler(Test.FooEvent, first_handler, priority=0)
        manager._register_handler(Test.FooEvent, second_handler, priority=-100)
        
        ev = Test.FooEvent("foo")
        manager.trigger(ev)
        self.wait_for_events()
        self.assertEqual(results, ["second", "first"])
        
        # Check that the regular register_handler() doesn't allow seeing
        # privileged priorities.
        results = []
        manager.reset()
        manager._register_handler(Test.FooEvent, first_handler, priority=-10)
        manager.register_handler(Test.FooEvent, second_handler, priority=-100)
        
        ev = Test.FooEvent("foo")
        manager.trigger(ev)
        self.wait_for_events()
        self.assertEqual(results, ["first", "second"])
       
    #enddef

    def test_emitter(self):

        class TestEmitter(Emitter):
            def __init__(self): super().__init__()
        #enddef

        emitter = TestEmitter()

        @self.check_called
        def observer(ev):
            self.assertEqual(ev.origin, emitter)
            self.assertIsInstance(ev, Test.FooEvent)
            self.assertEqual(ev.foo, "test")
        #enddef
        emitter.add_event_observer(observer)

        manager.reset()
        ev = emitter.emit_event(Test.FooEvent, "test")
        self.wait_for_events()
        self.assertTrue(observer.was_called())

        observer.clear_called()
        emitter.remove_event_observer(observer)
        manager.reset()
        ev = emitter.emit_event(Test.FooEvent, "test")
        self.wait_for_events()
        self.assertFalse(observer.was_called())


        with self.assertRaises(InvalidObserverExn):
            emitter.add_event_observer("blah")
        #endwith        

        with self.assertRaises(UnknownObserverExn):
            def another_observer(ev): pass
            emitter.remove_event_observer(another_observer)
        #endwith
        
    #enddef

    def test_relay(self):

        events = []
        def assertRelayedEvents(ev, expected_events):
            events.clear()
            manager.reset()
            manager.trigger(ev)
            self.wait_for_events()
            self.assertCountEqual(events, expected_events)
        #enddef

        class SelfObserver(object):
            def observer(self, bearing, ev):
                events.append((self, bearing, ev))
                return RELAY.CONTINUE
            #enddef
        #endclass
        
        BRG_CHILDREN = Bearing("Children")
        class ChildrenRelay(SelfObserver, BRG_CHILDREN.Relay):
            def __init__(self, name, children):
                super().__init__()
                self._name = name
                self._children = children
            #enddef
            @BRG_CHILDREN.adjacents_property
            def children(self): return list(self._children)
        #endclass

        child_foo = ChildrenRelay("foo", [])
        child_bar = ChildrenRelay("bar", [])
        child_baz = ChildrenRelay("baz", [])
        parent = ChildrenRelay("parent", [child_foo, child_bar, child_baz])

        # Test relaying to adjacents, and observers
        for c in parent.children:
            c.add_relay_event_observer(c.observer)
        #endfor
        parent.add_relay_event_observer(parent.observer)

        ev = Test.FooEvent("test", origin=parent)
        assertRelayedEvents(
            ev,
            ((parent, BRG_ORIGIN, ev),
             (child_foo, BRG_CHILDREN, ev),
             (child_bar, BRG_CHILDREN, ev),
             (child_baz, BRG_CHILDREN, ev))
        )

        # Test removing observers
        for c in parent.children:
            c.remove_relay_event_observer(c.observer)
        #endfor
        parent.remove_relay_event_observer(parent.observer)
        ev = Test.FooEvent("test", origin=parent)
        assertRelayedEvents(ev, ())

        # XXX: Tests for calling clear_event_observers() and friends.
        
        # Test indirect relays
        grandchild_quux = ChildrenRelay("quux", [])
        child_foo._children.append(grandchild_quux)
        grandchild_quux.add_relay_event_observer(grandchild_quux.observer)

        ev = Test.FooEvent("test", origin=parent)
        assertRelayedEvents(
            ev,
            ((grandchild_quux, BRG_CHILDREN, ev),)
        )
        grandchild_quux.remove_relay_event_observer(grandchild_quux.observer)
               
        # Test inheritance
        class MyChildrenRelay(ChildrenRelay): pass

        mychild = MyChildrenRelay("mychild", [])
        parent._children.append(mychild)
        mychild.add_relay_event_observer(mychild.observer)
        ev = Test.FooEvent("test", origin=parent)
        assertRelayedEvents(
            ev,
            ((mychild, BRG_CHILDREN, ev),)
        )
        mychild.remove_relay_event_observer(mychild.observer)

        # Test singleton adjacents
        BRG_SECRET = Bearing("Secret")
        class SecretRelay(SelfObserver, BRG_SECRET.Relay):
            def __init__(self, name, neighbour):
                super().__init__()
                self._name = name
                self._neighbour = neighbour
            #enddef
            def __repr__(self): return "SecretRelay<{}>".format(self._name)
            @BRG_SECRET.adjacents_property
            def neighbour(self): return self._neighbour

            @neighbour.setter
            def neighbour(self, value): self._neighbour = value
        #endclass
        secret_a = SecretRelay("a", None)
        secret_b = SecretRelay("b", secret_a)
        secret_a.add_relay_event_observer(secret_a.observer)
        ev = Test.FooEvent("test", origin=secret_b)
        assertRelayedEvents(
            ev,
            ((secret_a, BRG_SECRET, ev),)
        )
        secret_a.remove_relay_event_observer(secret_a.observer)

        # Test adjacents setters
        secret_c = SecretRelay("c", None)
        secret_a.neighbour = secret_c
        secret_c.add_relay_event_observer(secret_c.observer)
        ev = Test.FooEvent("test", origin=secret_b)
        assertRelayedEvents(
            ev,
            ((secret_c, BRG_SECRET, ev),)
        )

        # XXX: Test adjacents deleters?
        
        # Test subclass with new bearing
        BRG_PARENT = Bearing("Parent")
        class ExtendedRelay(ChildrenRelay, BRG_PARENT.Relay):
            def __init__(self, name, parent, children):
                super().__init__(name, children)
                self._parent = parent
            #enddef
            @BRG_PARENT.adjacents_property
            def parent(self): return self._parent
        #endclass
        foo = ExtendedRelay("foo", None, [])
        foo_parent = ExtendedRelay("foo_parent", None, [foo])
        foo._parent = foo_parent
        foo_child = ExtendedRelay("foo_child", foo, [])
        foo._children = [foo_child]

        foo_parent.add_relay_event_observer(foo_parent.observer)
        foo_child.add_relay_event_observer(foo_child.observer)
        ev = Test.FooEvent("test", origin=foo)
        assertRelayedEvents(
            ev,
            ((foo_parent, BRG_PARENT, ev),
             (foo_child, BRG_CHILDREN, ev))
        )

        # Test multiple inheritance
        class MultiRelay(SelfObserver,
                         BRG_CHILDREN.Relay,
                         BRG_PARENT.Relay):
            def __init__(self, name, parent, children):
                super().__init__()
                self._name = name
                self._parent = parent
                self._children = children
            #enddef
            @BRG_PARENT.adjacents_property
            def parent(self): return self._parent
            @BRG_CHILDREN.adjacents_property
            def children(self): return self._children
        #endclass

        bar = MultiRelay("bar", None, [])
        bar_parent = MultiRelay("bar_parent", None, [bar])
        bar._parent = bar_parent
        bar_child = MultiRelay("bar_child", bar, [])
        bar._children = [bar_child]

        bar_parent.add_relay_event_observer(bar_parent.observer)
        bar_child.add_relay_event_observer(bar_child.observer)
        ev = Test.BarEvent("test", origin=bar)
        assertRelayedEvents(
            ev,
            ((bar_parent, BRG_PARENT, ev),
             (bar_child, BRG_CHILDREN, ev))
        )
        
        # Test different error conditions
       
        bar._parent = secret_a
        manager.reset()
        with self.safeAssertRaises(util.TypecheckExn):
            ev = bar.emit_event(Test.BarEvent, "test")
            self.wait_for_events()
        #endwith

        manager.reset()
        class BadRelay(BRG_PARENT.Relay):
            def __init__(self):
                super().__init__()
            #enddef
        #endclass
        bad = BadRelay()
        with self.safeAssertRaises(TypeError):
            bad.emit_event(Test.FooEvent, "bad test")
            self.wait_for_events()
        #endwith

        # XXX: Any more error conditions to test?
        
    #enddef    

    def test_post_handlers(self):

        @self.check_called
        def post_handler(ev):
            pass
        #enddef

        def handler(ev):
            raise _PrivilegedHandlerPostActionExn(post_handler)
        #enddef

        manager.reset()
        manager._register_handler(Test.FooEvent, handler, priority=-1)
        
        ev = Test.FooEvent("foo")
        manager.trigger(ev)
        self.wait_for_events()
        self.assertTrue(post_handler.was_called())

        # Test that non-privileged handlers can't set post-handlers

        manager.reset()
        manager.register_handler(Test.FooEvent, handler)
        post_handler.clear_called()
        ev = Test.FooEvent("foo")
        manager.trigger(ev)
        self.wait_for_events()
        self.assertFalse(post_handler.was_called())
        
    #enddef
   
    # XXX TODO: Tests for stopping relay events.
    # XXX TODO: Tests for *_and_wait() functions.
    # XXX TODO: Test for wait_till_queue_empty()

    
#endclass
