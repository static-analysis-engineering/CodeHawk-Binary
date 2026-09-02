# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024  Aarno Labs, LLC
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


import logging
from enum import Enum
from typing import Optional, List


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


class DiagnosticCategory(str, Enum):
    """Classification of diagnostics for logging messages.

    Addition of a separate category to logging messages to
    enable downstream users to take appropriate action.

    USERDATA: data provided by the user via user data is
        incorrect or incomplete. This should be fixed by
        the user.

    TYPING: data provided by the user via header files or
        typing information provided in function annotations
        in the userdata is inconsistent or incomplete. This
        can often be fixed by the user.

    UNSUPPORTED: a known gap in analyzer support: an
        unimplemented instruction, expression form, or
        statement kind. Not fixable by the user: the function
        cannot currently be processed; it requires an extension
        to the analyzer.

    INTERNAL: an internal invariant was violated: analysis reached
        a program point without a fact (e.g., a reaching definition,
        or a non-error value) that the surrounding code assumed would
        be present. Not fixable by the user; indicates a possible
        defect in the analyzer rather than a known missing feature,
        and should be fixed by CodeHawk maintainers.
    """

    USERDATA = "USERDATA"
    TYPING = "TYPING"
    UNSUPPORTED = "UNSUPPORTED"
    INTERNAL = "INTERNAL"


class CHKLogger:

    def __init__(self) -> None:
        self._logger = logging.getLogger("silent")
        self._logger.addHandler(logging.NullHandler())
        self._diagnostic_count = 0

    @property
    def logger(self) -> logging.Logger:
        return self._logger

    @property
    def diagnostic_count(self) -> int:
        """Number of diagnostics logged since the last reset_diagnostic_count().
        """

        return self._diagnostic_count

    def reset_diagnostic_count(self) -> None:
        self._diagnostic_count = 0

    def diagnostic(
            self,
            category: DiagnosticCategory,
            msg: str,
            *args: object) -> None:
        """Log a diagnostic tagged with its category.

        The category is emitted as the first token of the message
        (e.g., UNSUPPORTED: no lifting support available for instruction ...).

        stacklevel=2 attributes the log record's %(module)s:%(lineno)d to
        the caller of diagnostic(), not to this method -- without it, every
        diagnostic would report its location as loggingutil:<this line>
        instead of the actual call site (e.g. XXprUtil:1005), which is what
        the [module:lineno] suffix exists to identify.
        """
        self._diagnostic_count += 1
        self._logger.error(
            category.value + ": " + msg, *args, stacklevel=2)

    def set_chkx_logger(
            self,
            initmsg: str = "",
            level: str = LogLevel.warning,
            logfilename: Optional[str] = None,
            mode: str = "a") -> None:

        if not level in LogLevel.all():
            level = LogLevel.warning.value

        newlogger = logging.getLogger("chkx")
        newlogger.setLevel(level)

        handler: logging.Handler
        if logfilename is not None:
            handler = logging.FileHandler(logfilename, mode=mode)
        else:
            handler = logging.StreamHandler()

        formatter = logging.Formatter(
            fmt="%(asctime)s:%(name)s:%(levelname)s:%(message)s [%(module)s:%(lineno)d]")
        handler.setFormatter(formatter)

        newlogger.addHandler(handler)

        self._logger = newlogger

        if len(initmsg) > 0:
            dst = logfilename if logfilename else "stderr"
            msg = initmsg + " with level: " + level + " to " + dst
            self._logger.info(msg)


chklogger = CHKLogger()
