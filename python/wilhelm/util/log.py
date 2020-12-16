# XXX DEPRECATED DO NOT USE XXX
# XXX REPLACED BY STANDARD LOGGING MODULE XXX

#
# Log : Logging mechanism
#

# import os
# import inspect
# import atexit

# __all__ = ("DERROR", "DWARN", "DINFO", "DBG", "DBG2")

# LVL_ERROR = 0
# LVL_WARN = 1
# LVL_INFO = 2
# LVL_DBG = 3
# LVL_DBG2 = 4

# #LEVEL = LVL_INFO
# LEVEL = LVL_DBG2
# LOG_FILE = None

# __level2str = {
#     LVL_ERROR : "ERROR",
#     LVL_WARN : "WARN",
#     LVL_INFO : "INFO",
#     LVL_DBG : "DBG",
#     LVL_DBG2 : "DBG2"
# }

# def __make_printer(lvl, full_debug=False):

#     lstr = __level2str[lvl]
#     def nop(s): return
#     def write_log(msg):
#         if LOG_FILE != None:
#             LOG_FILE.write(msg + os.linesep)
#             LOG_FILE.flush()
#         #endif
#         print(msg)
#     #enddef
    
#     if lvl > LEVEL: return nop

#     if full_debug:
#         def full_log(s):
#             fi = inspect.getframeinfo(inspect.stack()[1][0])
#             msg = "[%s (%s:%d)]\t%s" % (lstr, fi.filename, fi.lineno, s)
#             write_log(msg)
#         #enddef
#         return full_log
#     else:
#         def log(s):
#             msg = "[%s]\t%s" % (lstr, s)
#             write_log(msg)
#         #enddef
#         return log
#     #endif

# #enddef

# DERROR = __make_printer(LVL_ERROR)
# DWARN = __make_printer(LVL_WARN)
# DINFO = __make_printer(LVL_INFO)
# DBG = __make_printer(LVL_DBG, full_debug=True)
# DBG2 = __make_printer(LVL_DBG2, full_debug=True)

# def set_log_file(path):
#     global LOG_FILE
#     if LOG_FILE != None: LOG_FILE.close()
#     LOG_FILE = open(path, "a")
# #enddef

# @atexit.register
# def close_log_file():
#     global LOG_FILE
#     LOG_FILE.close()
# #enddef
