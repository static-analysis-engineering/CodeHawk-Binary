# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024-2026  Aarno Labs, LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ------------------------------------------------------------------------------


import json
import contextvars
from contextlib import contextmanager
import logging
from enum import Enum
from typing import Optional, List

_current_faddr: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "chkx_faddr", default=None)

@contextmanager
def function_context(faddr: str):
    token = _current_faddr.set(faddr)
    try:
        yield
    finally:
        _current_faddr.reset(token)


class LogLevel(str, Enum):
    """Simple type to restrict CLI log-level choices.

    Copied from Ricardo Baratto.
    """

    critical = "CRITICAL"
    error = "ERROR"
    warning = "WARNING"
    info = "INFO"
    debug = "DEBUG"

    @classmethod
    def all(cls) -> List['LogLevel']:
        return [x for x in cls]

    @classmethod
    def options(cls) -> List[str]:
        return [x.value for x in cls] + ["NONE"]


class NativeJsonFormatter(logging.Formatter):

    def format(self, record):
        log_payload = {
            "ts": self.formatTime(record, self.datefmt),
            "lvl": record.levelname,
            "faddr": getattr(record, "faddr", None),
            "msg": record.getMessage(),
            "module": record.module,
            "line": record.lineno,
            "log_id": getattr(record, "log_id", CHKLogID.MISC_NOTAGID_0001.value)
        }
        if record.exc_info:
            log_payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_payload)


class CHKLogID(str, Enum):

    MISC_ABORT_0001 = "MISC-ABORT-0001"
    MISC_NOTAGID_0001 = "MISC-NOTAGID-0001"

    RDEF_CLOBBER_0001 = "RDEF-CLOBBER-0001"
    RDEF_CLOBBER_0002 = "RDEF-CLOBBER-0002"

    RDEF_MISSING_0001 = "RDEF-MISSING-0001"
    RDEF_MISSING_0002 = "RDEF-MISSING-0002"
    RDEF_MISSING_0003 = "RDEF-MISSING-0003"

    RDEF_UNRESOLVED_0001 = "RDEF-UNRESOLVED-0001"

    RSLT_BRNOCC_0001 = "RSLT-BRNOCC-0001"
    RSLT_ERRCXPR_0001 = "RSLT-ERRCXPR-0001"
    RSLT_ERRCXPR_0002 = "RSLT-ERRCXPR-0002"
    RSLT_ERRCXPR_0003 = "RSLT-ERRCXPR-0003"
    RSLT_ERRFRZ_0001 = "RSLT-ERRFRZ-0001"   # raw frozen value (not simplified)
    RSLT_ERRGLB_0001 = "RSLT-ERRGLB-0001"
    RSLT_ERRVAL_0001 = "RSLT-ERRVAL-0001"
    RSLT_ERRVAL_0002 = "RSLT-ERRVAL-0002"
    RSLT_ERRVAL_0003 = "RSLT-ERRVAL-0003"
    RSLT_ERRVAL_0004 = "RSLT-ERRVAL-0004"
    RSLT_ERRVAL_0005 = "RSLT-ERRVAL-0005"
    RSLT_ERRVAL_0006 = "RSLT-ERRVAL-0006"
    RSLT_PRNOCC_0001 = "RSLT-PRNOCC-0001"   # predicated instruction condition
    RSLT_RANDOM_0001 = "RSLT-RANDOM-0001"
    RSLT_XCFALSE_0001 = "RSLT-XCFALSE-0001"
    RSLT_XCTRUE_0001 = "RSLT-XCTRUE-0001"

    UNSP_ASMINSTR_0001 = "UNSP-ASMINSTR-0001"
    UNSP_BINOP_0001 = "UNSP-BINOP-0001"
    UNSP_DATASTR_0001 = "UNSP-DATASTR-0001"
    UNSP_DATASTR_0002 = "UNSP-DATASTR-0002"
    UNSP_GLBVAR_0001 = "UNSP-GLBVAR-0001"
    UNSP_GLBVAR_0002 = "UNSP-GLBVAR-0002"
    UNSP_INDEXEXP_0001 = "UNSP-INDEXEXP-0001"
    UNSP_INDCALL_0001 = "UNSP-INDCALL-0001"
    UNSP_INDCALL_0002 = "UNSP-INDCALL-0002"
    UNSP_JMPTBL_0001 = "UNSP-JMPTBL-0001"
    UNSP_PTRXPR_0001 = "UNSP-PTRXPR-0001"
    UNSP_RETVAR_0001 = "UNSP-RETVAR-0001"
    UNSP_STCKARG_0001 = "UNSP-STCKARG-0001"

    USER_GLBDECL_0001 = "USER-GLBDECL-0001"  # missing decl of global variable
    USER_STRCTDEF_0001 = "USER-STRCTDEF-0001"   # missing struct definition
    USER_STRCTDEF_0002 = "USER-STRCTDEF-0002"   # idem


class IDLogger(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        """
        Interrupts the logging call and safely moves the dynamic 'log_id'
        from kwargs into the final 'extra' dictionary.
        """
        log_id = kwargs.pop('log_id', CHKLogID.MISC_NOTAGID_0001.value)
        extra = kwargs.setdefault('extra', {})
        extra['log_id'] = log_id
        extra.setdefault('faddr', _current_faddr.get())
        return msg, kwargs

    def log_with_id(self, level, log_id, msg, *args, **kwargs):
        kwargs['log_id'] = log_id.value
        self.log(level, msg, *args, **kwargs, stacklevel=4)

    def debug_id(self, log_id: CHKLogID, msg, *args, **kwargs):
        self.log_with_id(logging.DEBUG, log_id, msg, *args, **kwargs)

    def info_id(self, log_id: CHKLogID, msg, *args, **kwargs):
        self.log_with_id(logging.INFO, log_id, msg, *args, **kwargs)

    def warning_id(self, log_id: CHKLogID, msg, *args, **kwargs):
        self.log_with_id(logging.WARNING, log_id, msg, *args, **kwargs)

    def error_id(self, log_id: CHKLogID, msg, *args, **kwargs):
        self.log_with_id(logging.ERROR, log_id, msg, *args, **kwargs)

    def critical_id(self, log_id: CHKLogID, msg, *args, **kwargs):
        self.log_with_id(logging.CRITICAL, log_id, msg, *args, **kwargs)


class CHKLogger:

    def __init__(self) -> None:
        self._baselogger = logging.getLogger("silent")
        self._baselogger.addHandler(logging.NullHandler())
        self._logger = IDLogger(self._baselogger)

    @property
    def logger(self) -> IDLogger:
        return self._logger

    def set_chkx_logger(
            self,
            initmsg: str = "",
            level: str = LogLevel.warning,
            logfilename: Optional[str] = None,
            mode: str = "a",
            jlogfilename: Optional[str] = None,
            jlevel: str = LogLevel.info,
            jmode: str = "w") -> None:

        if not level in LogLevel.all():
            level = LogLevel.warning.value

        baselogger = logging.getLogger("chkx")
        baselogger.setLevel(logging.DEBUG)
        newlogger: IDLogger = IDLogger(baselogger, {})

        handler: logging.Handler
        if logfilename is not None:
            handler = logging.FileHandler(logfilename, mode=mode)
            handler.setLevel(level)
        else:
            handler = logging.StreamHandler()
            handler.setLevel(level)

        formatter = logging.Formatter(
            fmt="%(asctime)s:[%(log_id)s]:%(name)s:%(levelname)s:%(message)s [%(module)s:%(lineno)d]",
            defaults={"log_id": CHKLogID.MISC_NOTAGID_0001.value})
        handler.setFormatter(formatter)

        baselogger.addHandler(handler)

        if jlogfilename is not None:
            jsonhandler = logging.FileHandler(
                jlogfilename, encoding="utf-8", mode=jmode)
            jsonhandler.setLevel(jlevel)
            jsonhandler.setFormatter(NativeJsonFormatter())
            baselogger.addHandler(jsonhandler)

        self._logger = newlogger

        if len(initmsg) > 0:
            dst = logfilename if logfilename else "stderr"
            msg = initmsg + " with level: " + level + " to " + dst
            self._logger.info(msg)


chklogger = CHKLogger()
