#
# tester : Unit testing harness for Wilhelm
#

import sys
import os
import pkgutil
import importlib
import unittest
import subprocess

from .util.log import *
from . import util

class Exn(Exception): pass
class NoTestsExn(Exn): pass
class InvalidTestClassExn(Exn): pass
class TestSetupExn(Exn): pass

def get_tests_from_module(mod_name, pkgname):
    mod = importlib.import_module("." + mod_name, package=pkgname)
    # Don't reload as it will cause problems with other modules referencing
    # the previous module.
    #importlib.reload(mod)
    if "Test" in mod.__dict__:
        t = mod.__dict__["Test"]
        if issubclass(t, unittest.TestCase):
            loader = unittest.TestLoader()
            return loader.loadTestsFromTestCase(t)
        else:
            raise InvalidTestClassExn("Invalid test class in module {}".format(mod.__name__))
        #endif
    else:
        raise NoTestsExn("No tests found in module {}.".format(mod.__name__))
    #endif
#enddef   

def run_tests(mod_names=None, stream=None, verbosity=2):

    if stream == None:
        LOG = print
    else:
        def LOG(s): stream.write(s + os.linesep)
    #endifn
    
    pkg = sys.modules[sys.modules[__name__].__package__]
    
    suites = []

    if mod_names == None:
        main_modules = [mod_name for (_, mod_name, is_pkg)
                        in pkgutil.iter_modules(pkg.__path__)
                        if not is_pkg]
        util_modules = ["util." + mod_name
                        for (_, mod_name, is_pkg)
                        in pkgutil.iter_modules(util.__path__)
                        if not is_pkg]
        mod_names = main_modules + util_modules
    #endif
   
    for mod_name in mod_names:
        try:
            tests = get_tests_from_module(mod_name, pkg.__name__)
            suites.append(tests)
        except (InvalidTestClassExn, NoTestsExn) as e:
            LOG("WARNING: {}".format(e.args[0]))
        except ImportError:
            LOG("WARNING: Failed to import module '{}'".format(mod_name))
        #endtry
    #endfor
    
    top_suite = unittest.TestSuite(suites)

    tester = unittest.TextTestRunner(stream=stream, verbosity=verbosity)
    return tester.run(top_suite)
    
#enddef
