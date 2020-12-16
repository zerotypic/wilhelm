#
# asyncutils : Utility functions for working with asyncio
#

import asyncio
import time

from PyQt5.QtWidgets import QApplication

from . import setup_logger

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = setup_logger(__name__)

__counter = 0

def run_task_till_done(coro):
    '''
    Runs a coroutine as a task, blocking till it is complete.
    Similar to asyncio.run_until_complete(), but works when the event loop
    has already been started elsewhere.
    '''
    global __counter
    __counter += 1
    mycounter = __counter
    DBG("Started run_task_till_done #%d for coro %r", mycounter, coro)
    app = QApplication.instance()
    t = asyncio.get_event_loop().create_task(coro)
    DBG("task #%d = %r, beginning loop.", mycounter, t)
    while not t.done():
        app.processEvents()
        time.sleep(0.01)
    #endwhile
    DBG("task #%d, task completed: %r", mycounter, t)
    return t
    
#enddef
