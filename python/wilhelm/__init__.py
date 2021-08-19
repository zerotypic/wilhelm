import sys
import logging
import importlib
import inspect
import asyncio
from enum import Enum, auto

from . import util

(LOG, DCRIT, DERROR, DWARN, DINFO, DBG) = util.setup_logger(__name__)

class Feature(Enum):
    EVENT = ("event", "ida_events")
    QNAME = ("qname",)
    AST = ("ast",)
    PATH = ("path",)
    MODULE = ("module",)
#endclass

CORE_FEATURES = (Feature.EVENT,
                 Feature.QNAME,
                 Feature.AST)

def initialize(*args):

    thismod = sys.modules[__name__]

    features = set(CORE_FEATURES + args)
    
    for feat in features:
        DINFO("Setting up feature: {}".format(feat))
        for modname in feat.value:
            mod = importlib.import_module("." + modname, package=__name__)
            if "__all__" in mod.__dict__:
                # Import values specified in __all__ into our namespace.
                for n in mod.__all__:
                    if not n in mod.__dict__:
                        DWARN("Feature module {} __all__ contains unknown value {}".format(modname, n))
                        continue
                    #endif
                    if n in thismod.__dict__:
                        DWARN("Feature module {} __all__ overrides existing value {}.".format(modname, n))
                    #endif
                    thismod.__dict__[n] = mod.__dict__[n]
                #endfor
            #endif

            if "_module_init" in mod.__dict__:
                # Run module initializer.
                if inspect.iscoroutinefunction(mod._module_init):
                    asyncio.get_event_loop().create_task(mod._module_init(mod))
                else:
                    mod._module_init(mod)
                #endif
            #endif
        #endfor
    #endfor
    
#enddef
