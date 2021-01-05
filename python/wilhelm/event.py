#
# event : Event management
#

import asyncio
import logging
import enum
import operator

from inspect import isawaitable

from . import util
from .util import TYPECHECK
from .util import asyncutils

class Exn(Exception): pass
class UnknownHandlerExn(Exn): pass
class InvalidHandlerExn(Exn): pass
class InvalidObserverExn(Exn): pass
class UnknownObserverExn(Exn): pass
class InvalidBearingExn(Exn): pass
class InvalidRelayExn(Exn): pass

class LoopExn(Exn): pass
class LoopStartedExn(LoopExn): pass
class LoopNotStartedExn(LoopExn): pass
class EventTaskCancelledExn(LoopExn): pass
class EventTaskExceptionExn(LoopExn): pass
class CleanupCompletedEventExn(LoopExn): pass

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
        self.__origin = origin
        self.__tag = None if tag == None else str(tag)

        self.__handled = asyncio.Event()
        self.__observed = asyncio.Event()
        self.__handler_task = None
        self.__observer_task = None
        self.__exns = None
    #enddef

    @property
    def tag(self): return self.__tag

    @property
    def origin(self): return self.__origin
    
    def is_handled(self): return self.__handled.is_set()
    def is_observed(self): return self.__observed.is_set()
    def is_completed(self): return self.is_handled() and self.is_observed()

    def mark_handled(self, exns=None):
        if exns != None and exns != []:
            if self.__exns == None: self.__exns = []
            self.__exns += exns
        #endif
        DBG("Marking event %r as handled.", self)
        self.__handled.set()
    #enddef

    def mark_observed(self, exns=None):
        if exns != None and exns != []:
            if self.__exns == None: self.__exns = []
            self.__exns += exns
        #endif
        self.__observed.set()
    #enddef

    def clear_handled(self): self.__handled.clear()
    def clear_observed(self): self.__observed.clear()
    def clear_all(self):
        self.clear_handled()
        self.clear_observed()
    #enddef
    
    def has_exceptions(self): return self.__exns != None
    
    def get_exceptions(self):
        '''Retrieve any exceptions raised by event handlers while this event was
        being processed. Returns a list of 2-tuples of the form (h, exn)
        where 'h' is the handler that raised exception 'exn'.
        '''
        return list(self.__exns) if self.__exns != None else []
    #enddef
    
    async def wait_till_completed(self):
        await asyncio.gather(self.__handled.wait(),
                             self.__observed.wait())
    #enddef

    @property
    def _handler_task(self): return self.__handler_task
    @_handler_task.setter
    def _handler_task(self, hnd): self.__handler_task = hnd

    @property
    def _observer_task(self): return self.__observer_task
    @_observer_task.setter
    def _observer_task(self, hnd): self.__observer_task = hnd
    
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
    
    async def emit_event_async(self, evtype, *args, **kwargs):
        ev = evtype(*args, origin=self, **kwargs)
        await manager.trigger_async(ev)
        return ev
    #enddef
   
    # Wait for event to be handled before continuing.
    async def emit_event_and_wait(self, evtype, *args, **kwargs):
        ev = await self.emit_event_async(evtype, *args, **kwargs)
        await ev.wait_till_completed()
        return ev
    #enddef

    def _gather_observers(self): return self.__event_observers
    
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

    # acc is accumulator of all observers
    def _gather_relay_observers(self, bearing, acc):
        if bearing == BRG_ORIGIN:
            acc += self.__relay_event_observers
            return
        #endif

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
        for r in adjacents:
            acc += r.__relay_event_observers
            r._gather_relay_observers(bearing, acc)
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
        self._pending_events = set() # Pending events
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

    # Default event handler. This is used as a placeholder and never
    # actually executes.
    def _default_handler(self, ev):
        return
    
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
        Triggers an event.
        '''
        TYPECHECK(ev, Event)
        await self._q.put(ev)
        return ev
    #enddef

    async def trigger_and_wait(self, ev):
        ev = await self.trigger_async(ev)
        await ev.wait_till_completed()
        return ev
    #enddef
    
    def trigger(self, ev):
        '''Triggers an event synchronously without blocking.
        This functions immediately puts a new Event into the event
        queue. If the queue is full, it will raise
        asyncio.QueueFull. Currently, the queue is defined to have an
        infinite size, so the exception should never be raised.
        '''
        DBG("Called event.manager.trigger on event %r", ev)
        TYPECHECK(ev, Event)
        self._q.put_nowait(ev)
        return ev
    #enddef

    async def wait_till_queue_empty(self):
        '''Waits till the event queue is empty.'''
        await self._q.join()
    #enddef
    
    def last_exn_event(self):
        '''Returns the last event whose handlers/observers raised exceptions.'''
        return self._last_exn_event
    #enddef

    # Runs a function. If it returns an awaitable (i.e. it was probably a
    # coroutine function), await on the awaitable.
    async def _run_or_await(self, f, *args, **kwargs):
        DBG("Running function %r", f)
        r = f(*args, **kwargs)
        DBG("\tfunction returned: %r", r)
        if isawaitable(r): r = await r
        return r
    #enddef
    
    async def _run_handlers_task(self, ev, handlers):
        '''Run handlers for event. (internal helper function)

        Coroutine, that given a priority-handler list, calls the handlers
        for the event <ev>. If the handlers are coroutines, await them.
        Meant to be run as a task.

        :param ev: event whose handlers is being called
        :param handlers: A list of (priority, handler) tuples.
        :returns: a possibly empty list of exceptions raised by the handlers.
        '''

        DBG("_run_handlers_task, ev = %r, handlers = %r", ev, handlers)
        
        # Sort based on priority
        handlers.sort(key=operator.itemgetter(0))
            
        # Call all associated handlers.
        exns = []
        post_handlers = []
        DBG("Calling event handlers.")
        for (p, h) in handlers:
            try:
                await self._run_or_await(h, ev)
            except _PrivilegedHandlerPostActionExn as exn:
                if p < PRIORITY_MIN:
                    post_handlers.append(exn.post_handler)
                else:
                    DWARN("Non-privileged handler tried to set a post-handler, ignoring.")
                #endif
            except Exception as exn:
                exns.append((h, exn))
            #endtry
        #endfor
        DBG("Finished calling all event handlers.")

        if len(post_handlers) > 0:
            DBG("Post handlers have been registered, calling them now.")
            for ph in post_handlers:
                try:
                    await self._run_or_await(ph, ev)
                except Exception as exn:
                    exns.append((ph, exn))
                #endtry
            #endfor
            DBG("Finished calling post handlers.")
        #endif

        # XXX: THE BELOW CODE RAISES AN EXCEPTION, WRITE A WRAPPER TO
        # CATCH IT
        if LOG.isEnabledFor(logging.INFO) and exns != []:
            DINFO("Observers raised exceptions for event %r:", ev)
            for exn in exns: DINFO("\t%r", exn)
        #endif
        
        # Mark exception as handled.
        ev.mark_handled(exns=exns)
               
    #enddef

    def _process_handlers(self, ev):
        '''Process event handlers for event. (internal helper function)

        Gathers the list of event handlers registered for an event. If
        there are any, run them by creating a task that runs the coroutine
        _run_handlers_task().

        :param event: the event whose handlers are to be processed
        :returns: the task that was created to run the handlers, or None if
        no task was created.
        '''
        DBG("Processing handlers for event %r", ev)
        # First, gather all handlers.
        handlers = []
        evtype = type(ev)
        while True:

            # Because we have a default handler for the Event base class,
            # this loop will always be able to find a handler.           
            while not evtype in self._handler_map:
                evtype = evtype.__bases__[0]
            #endwhile

            evmap = self._handler_map[evtype]

            # General handlers for this type
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
        DBG("\thandlers = %r", handlers)
        if len(handlers) == 1 and handlers[0][1] == self._default_handler:
            # Only default handler was set, don't bother running it,
            # just mark as handled.
            DBG("\tOnly default handler, marked handled and continue.")
            ev.mark_handled()
            return None
        else:
            DBG("\tHandlers exist, create a task.")
            # Start a task to run the handlers.
            task = asyncio.get_event_loop().create_task(
                self._run_handlers_task(ev, handlers)
            )
            ev._handler_task = task
            return task
        #endif
        
    #enddef

    async def _run_observers_task(self, ev, emit_obvs, relay_obvs):
        '''Run observers for an event. (internal helper function)
 
        Coroutine that, given lists of emit-observers and relay-observers,
        calls the observers. If the observers are coroutines, await
        them.
        Meant to be run as a task.

        :param emit_obvs: List of emit-observers
        :param relay_obvs: List of (bearing, obvs) tuples, where bearing
        is a relay bearing and obvs is a list of relay-observers for that
        bearing.
        '''
        exns = []
        
        # First process emit observers.
        DBG("Calling emit observers.")
        for obv in emit_obvs:
            try:
                await self._run_or_await(obv, ev)
            except Exception as exn:
                exns.append((obv, exn))
            #endtry
        #endfor
        DBG("Finished calling emit observers.")

        # Now process relay observers.
        for (brg, obvs) in relay_obvs:
            DBG("Relaying to observers along %r", brg)
            for obv in obvs:
                try:
                    r = await self._run_or_await(obv, brg, ev)
                except Exception as exn:
                    exns.append((obv, exn))
                #endtry
                if r == RELAY.STOP:
                    DBG("Relay observer %r along bearing %r requested to stop relaying event %r",
                        obv, brg, ev)
                    break
                #endif
            #endfor
        #endfor
        DBG("Finished calling all relay observers.")

        if LOG.isEnabledFor(logging.INFO) and exns != []:
            INFO("Observers raised exceptions for event %r:", ev)
            for exn in exns: INFO("\t%r", exn)
        #endif
        
        ev.mark_observed(exns=exns)
        
    #enddef
    
    def _process_observers(self, ev):
        '''Process observers for an event.

        Given an event, gather both emit-observers and relay-observers of
        the event. If there are any, run them by starting a task that runs
        the coroutine _run_observers_task().

        :param ev: event whose observers are to be processed
        :returns: the task that was created to run the observers, or None if
        no task was created.
        '''
        origin = ev.origin
        # Gather emit-observers.
        emit_obvs = origin._gather_observers() if isinstance(origin, Emitter) else []

        # Gather relay-observers
        has_relay_observers = False
        relay_obvs = []
        if isinstance(origin, Relay):
            for brg in (BRG_ORIGIN, *origin._event_bearings()):
                obvs = []
                origin._gather_relay_observers(brg, obvs)
                if obvs != []: has_relay_observers = True
                relay_obvs.append((brg, obvs))
            #endfor
        #endif

        DBG("For event %r, emit_obvs = %r, relay_obvs = %r",
            ev, emit_obvs, relay_obvs)
        
        if emit_obvs == [] and has_relay_observers == False:
            # No observers found. Mark as observed and return.
            ev.mark_observed()
            return None
        else:
            # Start a task to run the observers.
            task = asyncio.get_event_loop().create_task(
                self._run_observers_task(ev, emit_obvs, relay_obvs)
            )
            ev._observer_task = task
            return task
        #endif
        
    #enddef

    def _cleanup_event(self, ev, handler_exn = None, observer_exn = None):
        '''Marks event as completed, and set exceptions. (internal helper function)'''
        DBG("Cleaning up event %r", ev)
        if ev.is_completed():
            raise CleanupCompletedEventExn("Cannot clean up completed event {!r}".format(ev))
        #endif
        if handler_exn != None: handler_exn = [(None, handler_exn)]
        if observer_exn != None: observer_exn = [(None, observer_exn)]
        if not ev.is_handled(): ev.mark_handled(exns=handler_exn)
        if not ev.is_observed(): ev.mark_observed(exns=observer_exn)
        # XXX: Cancel any currently running tasks?
    #enddef

    def _process_pending_events(self):
        '''Housekeeping on pending event list. (internal helper function)'''
        # XXX: Introduce some system of keeping track of stale events, and
        # forcefully cleaning them out.
        DBG("_process_pending_events: %r", self._pending_events)
        
        for ev in tuple(self._pending_events):
            DBG("\tev: %r", ev)
            if ev.is_completed():
                DBG("\tEvent %r has completed.", ev)
                if ev.has_exceptions():
                    DBG("\tEvent %r raised exceptions, recording.", ev)
                    self._last_exn_event = ev
                #endif
                self._pending_events.remove(ev)
                DBG("\tInform queue we're done with this event.")
                self._q.task_done()
            else:
                # XXX: Need to clean up logic here a bit, to test for the
                # different possible states more cleanly. Or, should
                # introduce some explicit event states with semantics
                # governing state transitions so we can reason about the
                # behaviour better.
                DBG("\tEvent %r not yet completed.", ev)
                handler_task = ev._handler_task
                observer_task = ev._observer_task
                DBG("\thandler_task = %r, observer_task = %r", handler_task, observer_task)
                if not handler_task.done() and \
                   (observer_task == None or not observer_task.done()): continue
               
                if handler_task.done() and handler_task.cancelled():
                    self._cleanup_event(ev, handler_exn=EventTaskCancelledExn(
                        "Event {!r}: handler task was cancelled.".format(ev)))
                elif handler_task.done() and handler_task.exception() != None:
                    self._cleanup_event(ev, handler_exn=EventTaskExceptionExn(
                        "Event {!r}: handler task raised exception {!r}".format(
                            ev, handler_task.exception()),
                        handler_task.exception()
                    ))
                elif observer_task == None:
                    # We're probably in the transient state where
                    # handler_task is done, but the observer_task hasn't
                    # been setup yet. Just ignore and continue.
                    continue
                elif observer_task.done() and observer_task.cancelled():
                    self._cleanup_event(ev, observer_exn=EventTaskCancelledExn(
                        "Event {!r}: observer task was cancelled.".format(ev)))
                elif observer_task.done() and observer_task.exception() != None:
                    self._cleanup_event(ev, observer_exn=EventTaskExceptionExn(
                        "Event {!r}: observer task raised exception {!r}".format(
                            ev, observer_task.exception()),
                        handler_task.exception()
                    ))
                #endif
            #endif
        #endfor

        DBG("Leaving _process_pending_events")
        
    #enddef
    
    async def _event_loop(self):
        
        # Helper function for running event processor functions defined
        # above. Runs a processor, and if it returns a task, register the
        # continuation <cont> to run after the task completes. Otherwise,
        # run <cont> immediately.
        # XXX: Currently not used. We should profile to find out whether
        # there's a performance difference between using the _stageN
        # functions below, and using this.
        def _process_and_continue(processor, args, cont):
            task = processor(*args)
            if task == None:
                return cont()
            else:
                task.add_done_callback(cont)
                return task
            #endif
        #enddef
        
        def _stage1(ev):
            DBG("Stage 1: %r", ev)
            try:
                handler_task = self._process_handlers(ev)
            except Exception as exn:
                DBG("\tHandler task resulted in exception, storing in event.")
                self._cleanup_event(ev, handler_exn=exn)
                # XXX: Should we call to _stage3 here to clean up?
                return
            #endtry
            if handler_task != None:
                DBG("\tHandler task created, adding done callback")
                handler_task.add_done_callback(lambda _: _stage2(ev))
            else:
                DBG("\tNo task needed.")
                _stage2(ev)
            #endif
        #enddef
        def _stage2(ev):
            DBG("Stage 2: %r", ev)
            try:
                observer_task = self._process_observers(ev)
            except Exception as exn:
                DBG("\tObserver task resulted in exception, storing in event.")
                self._cleanup_event(ev, observer_exn=exn)
                # We're either running as part of the event loop task, or
                # as a done callback of the stage1 task. In either case,
                # if we return from here, the event loop continues to run
                # normally.
                # XXX: Should we call into _stage3 here to clean up?
                return
            #endtry
            if observer_task != None:
                DBG("\tObserver task created, adding done callback")
                observer_task.add_done_callback(lambda _: _stage3(ev))
            else:
                DBG("\tNo task needed.")
                _stage3(ev)
            #endif
        #enddef
        def _stage3(ev):
            DBG("Stage 3: %r", ev)
            # XXX: What kind of exceptions should we catch here, if any?
            self._process_pending_events()
        #enddef
        
        while True:
            DBG("Waiting for event queue")
            try:
                ev = await asyncio.wait_for(self._q.get(), 0.5)
            except asyncio.TimeoutError:
                # No event, just process pending events
                DBG("No events, processing pending events.")
                self._process_pending_events()
                continue
            #endtry
                
            DBG("Handling event %r", ev)
            self._pending_events.add(ev)
            
            # First, process handlers. Register a callback for after
            # handlers have been processed, to process observers, and
            # register another callback for after observers have been
            # processed, to process pending events.
            # In the case where no tasks are created for each stage, run
            # the next stage immediately.
            # This code is a bit convoluted to avoid creating too many
            # task objects for the most common scenario, which is no
            # handlers and observers.

            # _process_and_continue(
            #     self._process_handlers, (ev,),
            #     lambda: _process_and_continue(
            #         self._process_observers, (ev,),
            #         self._process_pending_events
            #     )
            # )           
            
            # Begin the first stage.
            # XXX: Do we need to catch any exceptions here?
            _stage1(ev)

            DBG("Completed stages.")

        #endwhile
    #enddef

    def is_loop_started(self): return self._loop_task != None and not self._loop_task.done()
    
    def start_loop(self):
        def _loop_done_callback(future):
            DBG("Event loop returned! %r", future)
            exn = future.exception()
            if exn != None:
                DBG("Raising exception resulting in loop termination.")
                import traceback
                # XXX: Fix this traceback format, not printing correctly now.
                for l in traceback.format_exception(None, exn, exn.__traceback__): DBG("\t" + l[:-1])
                raise exn
            #endif
        #enddef
        if not self.is_loop_started():
            self._loop_task = asyncio.get_event_loop().create_task(self._event_loop())
            self._loop_task.add_done_callback(_loop_done_callback)
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
        def exn_handler(loop, context):
            DWARN("Exception in asyncio loop %r!", loop)
            DWARN("\tcontext = %r", context)
        #enddef
        asyncio.get_event_loop().set_exception_handler(exn_handler)

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
        return asyncutils.run_task_till_done(coro)
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
        await ev.wait_till_completed()
        if len(ev.get_exceptions()) > 0:
            raise ev.get_exceptions()[0][1]
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
            await bar_event.wait_till_completed()
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
            await ev.wait_till_completed()
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
            await tagged_bar_event.wait_till_completed()
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
        with self.safeAssertRaises(InvalidBearingExn):
            DBG("FOOFOO sending event")
            ev = bar.emit_event(Test.BarEvent, "test")
            self.wait_for_events()
            DBG("FOOFOO completed wait")
        #endwith

        class BadRelay(BRG_PARENT.Relay):
            def __init__(self):
                super().__init__()
            #enddef
        #endclass
        bad = BadRelay()

        manager.reset()
        with self.safeAssertRaises(TypeError):
            bad.emit_event(Test.FooEvent, "bad test")
            self.wait_for_events()
        #endwith

        # Test with a handler registered.
        manager.reset()
        manager.register_handler(Test.FooEvent, lambda _: None)
        with self.safeAssertRaises(TypeError):
            bad.emit_event(Test.FooEvent, "bad test")
            self.wait_for_events()
        #endwith

        # Test with an observer registered.
        manager.reset()
        bar.add_relay_event_observer(lambda _: None)
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
