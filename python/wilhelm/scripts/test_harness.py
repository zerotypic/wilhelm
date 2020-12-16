#!/usr/bin/python3 -u
#
# test_harness : Harness for running unit tests.
#

import sys
import os
import argparse

TEST_BINARY = os.path.abspath(os.path.join(
    os.path.dirname(__file__),
    "..", "test-binaries", "unit-test-binary"))
HARNESS_PATH = os.path.abspath(__file__)
IDA_PATH = "ida"

def launch_in_ida(args, argv):

    import subprocess
    
    script_args = ["-X"] + argv[1:]
    script_cmdline = "{} {}".format(HARNESS_PATH, " ".join(script_args))

    ida_cmdline = [args.ida_path,
                   "-B",
                   '-S{}'.format(script_cmdline),
                   args.test_binary]

    print("Launching IDA Pro.")

    try:
        result = subprocess.check_output(ida_cmdline)
    except subprocess.CalledProcessError as e:
        print("WARNING: IDA returned error code {}".format(e.returncode))
        result = e.output
    #endtry
        
    print(result.decode("utf-8"))
    return 0

#enddef

def do_tests(args):

    import idaapi
    import unittest
    import importlib
    import importlib.util

    # Wait for analysis to complete.
    idaapi.auto_wait()

    # Setup logging
    import logging
    logging.basicConfig(stream=sys.__stdout__)
    fh = logging.FileHandler("/tmp/wilhelm_test_harness.log", "w")
    fh.setFormatter(logging.Formatter(fmt="%(levelname)s\t%(name)s\t%(message)s"))
    logging.getLogger().addHandler(fh)
    
    def dynload_module(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        return mod
    #enddef
    
    wilhelm_path = os.path.abspath("..")
    
    # Load wilhelm code from our parent subdirectory.
    wilhelm = dynload_module("wilhelm", os.path.join(wilhelm_path, "__init__.py"))
    tester = dynload_module("wilhelm.tester", os.path.join(wilhelm_path, "tester.py"))

    if args.debug:
        wilhelm.LOG.setLevel(logging.DEBUG)
    #endif
    
    try:
        mod_names = args.module if len(args.module) > 0 else None
        tester.run_tests(mod_names=mod_names, stream=sys.__stdout__)
    except Exception as e:
        import traceback
        (ty, val, tb) = sys.exc_info()
        traceback.print_exception(ty, val, tb, file=sys.__stdout__)
    #endtry

    # Exit properly using qexit().
    idaapi.qexit(0)
    
#enddef

def main():

    argv = []
    try:
        # If we're inside IDA Pro, use idc.ARGV
        import idc
        argv = idc.ARGV
    except ModuleNotFoundError:
        argv = sys.argv
    #endtry

    parser = argparse.ArgumentParser(
        description="Wilhelm unit test harness.",
    )
    parser.add_argument("-X", "--in-ida",
                        action="store_true",
                        help="Flag to indicate we're running inside IDA Pro")
    parser.add_argument("-b", "--test-binary",
                        type=str,
                        default=TEST_BINARY,
                        help="Binary used for unit testing")
    parser.add_argument("-i", "--ida-path",
                        type=str,
                        default=IDA_PATH,
                        help="Path to launch IDA Pro")
    parser.add_argument("-m", "--module",
                        action="append",
                        default=[],
                        help="Test only a specific module")
    parser.add_argument("-d", "--debug",
                        action="store_true",
                        help="Turn on debug logging.")
    
    args = parser.parse_args(args=argv[1:])

    if args.in_ida:
        # We're in IDA, do the tests.
        return do_tests(args)
    else:
        # Not in IDA, re-launch into IDA
        return launch_in_ida(args, argv)
    #endif

#enddef


if __name__ == "__main__": sys.exit(main())
