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
import datetime
import logging
import os
import subprocess
import sys
from enum import Enum

from typing import (
    Dict, Optional, List, Iterator, TYPE_CHECKING, Any, MutableMapping)

# Work around mypy issue with LoggerAdapter: https://github.com/python/typeshed/issues/7855
if TYPE_CHECKING:
    _LoggerAdapter = logging.LoggerAdapter[logging.Logger]
else:
    _LoggerAdapter = logging.LoggerAdapter


_current_faddr: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "chkx_faddr", default=None)

@contextmanager
def function_context(faddr: str) -> Iterator[None]:
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

    def payload(self, record: logging.LogRecord) -> Dict[str, Any]:
        log_payload: Dict[str, Any] = {
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
        return log_payload

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(self.payload(record))


class CHKLogID(str, Enum):

    INTF_XDATA_0001 = "INTF-XDATA-0001"    # incompatible data in xdata
    INTF_XDATA_0002 = "INTF-XDATA-0002"
    INTF_XDATA_0003 = "INTF-XDATA-0003"

    MISC_ABORT_0001 = "MISC-ABORT-0001"
    MISC_NOTAGID_0001 = "MISC-NOTAGID-0001"   # no tag-id: not yet tagged

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
    RSLT_ERRVAL_0007 = "RSLT-ERRVAL-0007"
    RSLT_ERRVAL_0008 = "RSLT-ERRVAL-0008"
    RSLT_ERRVAL_0009 = "RSLT-ERRVAL-0009"
    RSLT_ERRVAL_0010 = "RSLT-ERRVAL-0010"

    RSLT_ITNOCC_0001 = "RSLT-ITNOCC-0001"   # thumb IfThen condition

    RSLT_PRNOCC_0001 = "RSLT-PRNOCC-0001"   # predicated instruction condition
    RSLT_PRNOCC_0002 = "RSLT-PRNOCC-0002"
    RSLT_RANDOM_0001 = "RSLT-RANDOM-0001"
    RSLT_UNTYPED_0001 = "RSLT-UNTYPED-0001"
    RSLT_XCFALSE_0001 = "RSLT-XCFALSE-0001"
    RSLT_XCTRUE_0001 = "RSLT-XCTRUE-0001"

    UNSP_ASMINSTR_0001 = "UNSP-ASMINSTR-0001"
    UNSP_BINOP_0001 = "UNSP-BINOP-0001"
    UNSP_DATASTR_0001 = "UNSP-DATASTR-0001"
    UNSP_DATASTR_0002 = "UNSP-DATASTR-0002"
    UNSP_DATASTR_0003 = "UNSP-DATASTR-0003"
    UNSP_DATASTR_0004 = "UNSP-DATASTR-0004"
    UNSP_DATASTR_0005 = "UNSP-DATASTR-0005"
    UNSP_GLBVAR_0001 = "UNSP-GLBVAR-0001"
    UNSP_GLBVAR_0002 = "UNSP-GLBVAR-0002"
    UNSP_GLBVAR_0003 = "UNSP-GLBVAR-0003"
    UNSP_GLBVAR_0004 = "UNSP-GLBVAR-0004"
    UNSP_IFTHEN_0001 = "UNSP-IFTHEN-0001"
    UNSP_INDEXEXP_0001 = "UNSP-INDEXEXP-0001"
    UNSP_INDCALL_0001 = "UNSP-INDCALL-0001"
    UNSP_INDCALL_0002 = "UNSP-INDCALL-0002"
    UNSP_JMPTBL_0001 = "UNSP-JMPTBL-0001"
    UNSP_OPRVALUE_0001 = "UNSP-OPRVALUE-0001"
    UNSP_PTRXPR_0001 = "UNSP-PTRXPR-0001"
    UNSP_PTRXPR_0002 = "UNSP-PTRXPR-0002"
    UNSP_REGLOC_0001 = "UNSP-REGLOC-0001"
    UNSP_STCKARG_0001 = "UNSP-STCKARG-0001"
    UNSP_UNOP_0001 = "UNSP-UNOP-0001"

    USER_FNPROTO_0001 = "USER-FNPROTO-0001"
    USER_FNPROTO_0002 = "USER-FNPROTO-0002"
    USER_FNPROTO_0003 = "USER-FNPROTO-0003"
    USER_GLBDECL_0001 = "USER-GLBDECL-0001"  # missing decl of global variable
    USER_GLBDECL_0002 = "USER-GLBDECL-0002"
    USER_GLBDECL_0003 = "USER-GLBDECL-0003"
    USER_GLBDECL_0004 = "USER-GLBDECL-0004"
    USER_STRCTDEF_0001 = "USER-STRCTDEF-0001"   # missing struct definition
    USER_STRCTDEF_0002 = "USER-STRCTDEF-0002"   # idem
    USER_STRCTDEF_0003 = "USER-STRCTDEF-0003"   # idem
    USER_UNTYPEDSSA_0001 = "USER-UNTYPEDSSA-0001"
    USER_UNTYPEDST_0001 = "USER-UNTYPEDST-0001"


# Log-id categories (the first component of the log-id), with the party that
# is expected to act on them, and the recommended action. Used, together with
# _subcategory_info (keyed by the first two components of the log-id), to
# construct the recommendations in the json log file.
_category_info: Dict[str, Dict[str, str]] = {
    "USER": {
        "audience": "user",
        "description": "missing or incomplete user-provided data",
        "action": (
            "Provide the missing declarations (e.g., global variable "
            "declarations, struct definitions) in the header file(s) "
            "supplied with the analysis, and rerun.")},
    "INTF": {
        "audience": "user",
        "description": (
            "incompatibility between the analysis results (xdata) and "
            "the python frontend"),
        "action": (
            "Check that the analysis results were produced by a version "
            "of the CodeHawk core compatible with this version of "
            "CodeHawk-Binary; if so, report to the CodeHawk maintainers.")},
    "RDEF": {
        "audience": "user/maintainer",
        "description": "missing, clobbered, or unresolved reaching definitions",
        "action": "See the actions of the individual subcategories."},
    "RSLT": {
        "audience": "maintainer",
        "description": (
            "analysis results that could not be used for lifting (error "
            "values, unsimplified frozen values, constant conditions)"),
        "action": (
            "The affected expressions are lifted as temporaries; the "
            "lifting of the listed functions is less precise. Report to "
            "the CodeHawk maintainers if this impedes understanding.")},
    "UNSP": {
        "audience": "maintainer",
        "description": "constructs not (yet) supported by the lifter",
        "action": (
            "Not fixable by the user; requires an extension of the "
            "analyzer. Report the log-ids to the CodeHawk maintainers.")},
    "MISC": {
        "audience": "maintainer",
        "description": "miscellaneous (aborted liftings, untagged messages)",
        "action": "See the actions of the individual subcategories."}
}


_subcategory_info: Dict[str, Dict[str, str]] = {
    "INTF-XDATA": {
        "description": "xdata is incompatible with the python front end"
    },
    "MISC-ABORT": {
        "description": "lifting aborted",
        "action": (
            "The listed functions were not lifted. Report them to the "
            "CodeHawk maintainers.")
    },
    "MISC-NOTAGID": {
        "description": "message without a log-id",
        "action": "Assign log-ids to the messages at the reported locations."
    },
    "RDEF-CLOBBER": {
        "description": (
            "one of the reaching definitions of a register is a call where the "
            "register was clobbered"),
        "action": (
            "check if the reaching definition is legitimate; if not, remove the "
            "reaching definition via the userdata. Otherwise report to the "
            "CodeHawk maintainers")
    },
    "RDEF-MISSING": {
        "description": "the reaching definition of a variable is missing",
        "action": (
            "check if the variable is initialized (in the assembly code); "
            "if so, report to the CodeHawk maintainers")
    },
    "RDEF-UNRESOLVED": {
        "description": (
            "the address of a reaching definition is not present in the "
            "provenance data, that is, the defining instruction is not "
            "present in the lifting or did not register its definition"),
        "action": "report to the CodeHawk maintainers"
    },
    "RSLT-BRNOCC": {
        "description": "conditional branch instruction without condition",
        "action": "report to the CodeHawk maintainers"
    },
    "RSLT-ERRCXPR": {
        "description": (
            "the (symbolic) value of a memory load cannot be converted to a "
            "valid C expression."),
        "action": (
            "check if the type of the memory location is fully specified; if "
            "not, add type annotations to the userdata (for stack locations) "
            "or header file (for global variables), "
            "otherwise report to the CodeHawk maintainers")
    },
    "RSLT-ERRFRZ": {
        "description": (
            "a variable in a branch or predicate condition is an unresolved "
            "temporary bridge variable"),
        "action": "report to the CodeHawk maintainers"
    },
    "RSLT-ERRGLB": {
        "description": (
            "the change in a global variable may not be correctly represented"),
        "action": "report to the CodeHawk maintainers"
    },
    "RSLT-ERRVAL": {
        "description": (
            "a memory value or memory location cannot be resolved"),
        "action": "report to the CodeHawk maintainers"
    },
    "RSLT-ITNOCC": {
        "description": "thumb ifthen instruction without condition",
        "action": "report to the CodeHawk maintainers"
    },
    "RSLT-PRNOCC": {
        "description": "predicated instruction without predicate",
        "action": "report to the CodeHawk maintainers"
    },
    "RSLT-RANDOM": {
        "description": (
            "the lifting encountered a constant with unknown value"),
        "action": "report to the CodeHawk maintainers"
    },
    "RSLT-UNTYPED": {
        "description": (
            "the lifting contains an untyped placeholder variable caused "
            "by incomplete resolution of a memory value or condition"),
        "action": "report to the CodeHawk maintainers"
    },
    "RSLT-XCFALSE": {
        "description": (
            "the lifting encountered a constant condition False; this often "
            "signifies incomplete analysis, e.g., because of unrecognized "
            "function call side effects"),
        "action": (
            "inspect whether this condition is indeed constant False "
            "(in rare cases this happens); if not, review whether functions "
            "may need to be annotated with side effects (via attributes in "
            "the header file), or report to CodeHawk maintainers")
    },
    "RSLT-XCTRUE": {
        "description": (
           "the lifting encountered a constant condition True; this often "
            "signifies incomplete analysis, e.g., because of unrecognized "
            "function call side effects"),
        "action": (
            "inspect whether this condition is indeed constant True "
            "(in rare cases this happens); if not, review whether functions "
            "may need to be annotated with side effects (via attributes in "
            "the header file), or report to CodeHawk maintainers")
    },
    "UNSP-ASMINSTR": {
        "description": (
            "the function to be lifted contains an assembly instruction for "
            "which lifting is not yet supported"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-BINOP": {
        "description": (
            "the function to be lifted contains a binary operation for which "
            "lifting is not yet supported"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-DATASTR": {
        "description": (
            "the function to be lifted contains an access path into a data "
            "structure variable on the stack that is not yet supported (e.g., "
            "an index into an array within a struct field)"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-GLBVAR": {
        "description": (
            "the function to be lifted contains an access path into a data "
            "structure variable global variable that is not yet supported"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-IFTHEN": {
        "description": (
            "the function to be lifted contains an IT (Thumb) instruction with "
            "a pattern not yet supported"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-INDEXEXP": {
        "description": (
            "the function to be lifted contains a pointer-arithmetic expression "
            "that is not yet supported"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-INDCALL": {
        "description": (
            "the function to be lifted contains an indirect call that is not "
            "yet supported"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-JMPTBL": {
        "description": (
            "the function to be lifted contains a jumptable idiom that is not "
            "yet supported"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-OPRVALUE": {
        "description": (
            "the low-level C representation of the operand right-hand side value "
            "is not yet supported"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-PTRXPR": {
        "description": (
            "the function to be lifted contains a kind of pointer expression "
            "that is not yet supported"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-REGLOC": {
        "description": (
            "a register is referenced for which no location and size is available"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-STCKARG": {
        "description": (
            "the function to be lifted contains a kind of stack argument that "
            "is not yet supported"),
        "action": "report to CodeHawk maintainers"
    },
    "UNSP-UNOP": {
        "description": (
            "the function to be lifted contains a unary operation for which "
            "lifting is not yet supported"),
        "action": "report to CodeHawk maintainers"
    },
    "USER-FNPROTO": {
        "description": (
            "function prototype (signature) is missing; a function cannot be "
            "lifted without a valid function signature"),
        "action": "provide a function prototype in the header file"
    },
    "USER-GLBDECL": {
        "description": (
            "reference to a global variable that was not defined in the header "
            "file"),
        "action": (
            "provide a definition of the global variable in the header file "
            "with gv_<address>, e.g., int gv_430000 (no 0x), or give the "
            "global variable a name  in the header file (e.g., int my_globalvar) "
            "and connect the name with the address in the symbolic-addresses "
            "section of the userdata")
    },
    "USER-STRCTDEF": {
        "description": (
            "reference to a field of a struct that is not defined or has an "
            "opaque definition"),
        "action": (
            "add a full definition of the struct to the header file")
    },
    "USER-UNTYPEDSSA": {
        "description": "the lifting contains an untyped register variable",
        "action": (
            "add a register-variable intro with the type to the "
            "function annotations in the userdata")
    },
    "USER-UNTYPEDST": {
        "description": "the lifting contains an untyped stack variable",
        "action": (
            "add a stack-variable intro with the type to the function "
            "annotations in the userdata")
    }
}


_level_rank: Dict[str, int] = {
    "CRITICAL": 50, "ERROR": 40, "WARNING": 30, "INFO": 20, "DEBUG": 10}

# maximum number of function addresses listed per log-id / recommendation
_max_listed = 20


def log_id_category(log_id: str) -> str:
    return log_id.split("-")[0]


def log_id_subcategory(log_id: str) -> str:
    """Return the first two components of the log-id (e.g., RDEF-CLOBBER)."""
    return "-".join(log_id.split("-")[:2])


def _subcategory_description(subcat: str) -> str:
    return _subcategory_info.get(subcat, {}).get(
        "description", "unknown log-id subcategory")


def _max_level(levels: List[str]) -> str:
    return max(levels, key=lambda lvl: _level_rank.get(lvl, 0))


def json_log_digest(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a summary of the log entries.

    Entries are grouped by level, by log-id category, by log-id subcategory,
    by log-id, and by function.
    """
    by_level: Dict[str, int] = {}
    by_category: Dict[str, int] = {}
    by_subcategory: Dict[str, int] = {}
    by_function: Dict[str, int] = {}
    log_ids: Dict[str, Dict[str, Any]] = {}
    no_function = 0

    for e in entries:
        lvl = e.get("lvl", "NOTSET")
        log_id = e.get("log_id", CHKLogID.MISC_NOTAGID_0001.value)
        faddr = e.get("faddr")
        by_level[lvl] = by_level.get(lvl, 0) + 1
        cat = log_id_category(log_id)
        by_category[cat] = by_category.get(cat, 0) + 1
        subcat = log_id_subcategory(log_id)
        by_subcategory[subcat] = by_subcategory.get(subcat, 0) + 1
        if faddr is None:
            no_function += 1
        else:
            by_function[faddr] = by_function.get(faddr, 0) + 1
        rec = log_ids.setdefault(
            log_id,
            {"log_id": log_id,
             "count": 0,
             "levels": [],
             "functions": [],
             "example": e.get("msg"),
             "location": str(e.get("module")) + ":" + str(e.get("line"))})
        rec["count"] += 1
        if lvl not in rec["levels"]:
            rec["levels"].append(lvl)
        if faddr is not None and faddr not in rec["functions"]:
            rec["functions"].append(faddr)

    log_id_summary: List[Dict[str, Any]] = []
    for rec in sorted(log_ids.values(), key=lambda r: (-r["count"], r["log_id"])):
        functions = rec["functions"]
        subcat = log_id_subcategory(rec["log_id"])
        log_id_summary.append({
            "log_id": rec["log_id"],
            "subcategory": subcat,
            "description": _subcategory_description(subcat),
            "count": rec["count"],
            "level": _max_level(rec["levels"]),
            "function_count": len(functions),
            "functions": functions[:_max_listed],
            "example": rec["example"],
            "location": rec["location"]})

    return {
        "total": len(entries),
        "by_level": dict(sorted(
            by_level.items(), key=lambda p: -_level_rank.get(p[0], 0))),
        "by_category": dict(sorted(by_category.items(), key=lambda p: -p[1])),
        "by_subcategory": dict(sorted(
            by_subcategory.items(), key=lambda p: (-p[1], p[0]))),
        "functions_affected": len(by_function),
        "entries_without_function": no_function,
        "by_function": [
            {"faddr": faddr, "count": count}
            for (faddr, count) in sorted(
                    by_function.items(), key=lambda p: (-p[1], p[0]))],
        "by_log_id": log_id_summary}


def _merge_functions(recs: List[Dict[str, Any]]) -> List[str]:
    functions: List[str] = []
    for rec in recs:
        for faddr in rec["functions"]:
            if faddr not in functions:
                functions.append(faddr)
    return functions[:_max_listed]


def _by_severity(r: Dict[str, Any]) -> Any:
    return (-_level_rank.get(r["level"], 0), -r["count"])


def json_log_recommendations(digest: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return recommendations for follow-up action, one per log-id category.

    Each recommendation lists the subcategories present, with their own
    description, action (if specified), affected log-ids, and functions.
    Recommendations and subcategories are ordered by severity (highest level
    first), then by number of entries.
    """
    groups: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
    for rec in digest["by_log_id"]:
        log_id = rec["log_id"]
        groups.setdefault(log_id_category(log_id), {}).setdefault(
            log_id_subcategory(log_id), []).append(rec)

    result: List[Dict[str, Any]] = []
    for (cat, subgroups) in groups.items():
        info = _category_info.get(cat, {
            "audience": "maintainer",
            "description": "unknown log-id category",
            "action": "Report to the CodeHawk maintainers."})
        subcategories: List[Dict[str, Any]] = []
        for (subcat, recs) in subgroups.items():
            subinfo = _subcategory_info.get(subcat, {})
            subrec: Dict[str, Any] = {
                "subcategory": subcat,
                "description": _subcategory_description(subcat),
                "level": _max_level([rec["level"] for rec in recs]),
                "count": sum(rec["count"] for rec in recs)}
            if "audience" in subinfo:
                subrec["audience"] = subinfo["audience"]
            if "action" in subinfo:
                subrec["action"] = subinfo["action"]
            subrec["log_ids"] = [rec["log_id"] for rec in recs]
            subrec["functions"] = _merge_functions(recs)
            subcategories.append(subrec)
        result.append({
            "category": cat,
            "audience": info["audience"],
            "level": _max_level([r["level"] for r in subcategories]),
            "count": sum(r["count"] for r in subcategories),
            "description": info["description"],
            "action": info["action"],
            "subcategories": sorted(subcategories, key=_by_severity)})

    return sorted(result, key=_by_severity)


def _git_describe(path: str) -> Optional[str]:
    """Return git describe --always --dirty for the checkout containing path."""
    try:
        result = subprocess.run(
            ["git", "-C", path, "describe", "--always", "--dirty",
             "--abbrev=8"],
            capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def tool_versions() -> Dict[str, Optional[str]]:
    """Return the versions of the tools that produced the log entries.

    - chb: version of the CodeHawk-Binary python package (CHVersion)
    - chb-git: git revision of the CodeHawk-Binary checkout, if any
    - analyzer: path of the (OCaml) analyzer executable configured
    - analyzer-git: git revision of the checkout containing the analyzer
      executable (e.g., the codehawk repository for a dune build), if any;
      note that this is the revision of the sources, which may differ from
      the revision the executable was built from.

    Values that cannot be determined are None.
    """
    result: Dict[str, Optional[str]] = {}
    try:
        from chb.app.CHVersion import chbversion
        result["chb"] = chbversion
    except Exception:
        result["chb"] = None
    chbdir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    result["chb-git"] = _git_describe(chbdir)
    try:
        from chb.util.Config import Config
        analyzer: Optional[str] = Config().chx86_analyze
    except Exception:
        analyzer = None
    result["analyzer"] = analyzer
    result["analyzer-git"] = (
        _git_describe(os.path.dirname(os.path.realpath(analyzer)))
        if analyzer is not None and os.path.isfile(analyzer) else None)
    return result


class JsonLogHandler(logging.Handler):
    """Collects log entries and writes them as a single json document.

    The document is written when the handler is closed (at the latest by
    logging.shutdown, which is registered with atexit). In append mode the
    entries of an existing json log file (in the same format) are retained,
    and the digest is computed over all entries.
    """

    def __init__(self, filename: str, mode: str = "w") -> None:
        logging.Handler.__init__(self)
        self._filename = os.path.abspath(filename)
        self._entries: List[Dict[str, Any]] = []
        self._runs: List[Dict[str, Any]] = []
        self._written = False
        self._start = datetime.datetime.now().isoformat(timespec="seconds")
        if mode == "a":
            self._load_existing()

    def _load_existing(self) -> None:
        if not os.path.isfile(self._filename):
            return
        try:
            with open(self._filename, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            self._entries = list(data["entries"])
            self._runs = list(data.get("runs", []))
        except (ValueError, KeyError, TypeError):
            print(
                "Warning: existing json log file "
                + self._filename
                + " is not in the expected format; it will be overwritten",
                file=sys.stderr)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            formatter = self.formatter
            if isinstance(formatter, NativeJsonFormatter):
                payload = formatter.payload(record)
            else:
                payload = {"lvl": record.levelname, "msg": self.format(record)}
            self._entries.append(payload)
        except Exception:
            self.handleError(record)

    def write(self) -> None:
        self.acquire()
        try:
            if self._written:
                return
            runs = self._runs + [{
                "start": self._start,
                "end": datetime.datetime.now().isoformat(timespec="seconds"),
                "command": " ".join(sys.argv),
                "level": logging.getLevelName(self.level),
                "versions": tool_versions()}]
            digest = json_log_digest(self._entries)
            result = {
                "runs": runs,
                "digest": digest,
                "recommendations": json_log_recommendations(digest),
                "entries": self._entries}
            with open(self._filename, "w", encoding="utf-8") as fp:
                json.dump(result, fp, indent=2)
            self._written = True
        finally:
            self.release()

    def close(self) -> None:
        try:
            self.write()
        finally:
            logging.Handler.close(self)


class IDLogger(_LoggerAdapter):
    def process(
        self,
        msg: Any,
        kwargs: MutableMapping[str, Any]) -> tuple[Any, MutableMapping[str, Any]]:
        """
        Interrupts the logging call and safely moves the dynamic 'log_id'
        from kwargs into the final 'extra' dictionary.
        """
        log_id = kwargs.pop('log_id', CHKLogID.MISC_NOTAGID_0001.value)
        extra = kwargs.setdefault('extra', {})
        extra['log_id'] = log_id
        extra.setdefault('faddr', _current_faddr.get())
        return msg, kwargs

    def log_with_id(self, level: int, log_id: CHKLogID, msg: object, *args: Any, **kwargs: Any) -> None:
        kwargs['log_id'] = log_id.value
        self.log(level, msg, *args, **kwargs, stacklevel=4)

    def debug_id(self, log_id: CHKLogID, msg: object, *args: Any, **kwargs: Any) -> None:
        self.log_with_id(logging.DEBUG, log_id, msg, *args, **kwargs)

    def info_id(self, log_id: CHKLogID, msg: object, *args: Any, **kwargs: Any) -> None:
        self.log_with_id(logging.INFO, log_id, msg, *args, **kwargs)

    def warning_id(self, log_id: CHKLogID, msg: object, *args: Any, **kwargs: Any) -> None:
        self.log_with_id(logging.WARNING, log_id, msg, *args, **kwargs)

    def error_id(self, log_id: CHKLogID, msg: object, *args: Any, **kwargs: Any) -> None:
        self.log_with_id(logging.ERROR, log_id, msg, *args, **kwargs)

    def critical_id(self, log_id: CHKLogID, msg: object, *args: Any, **kwargs: Any) -> None:
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
            jsonhandler = JsonLogHandler(jlogfilename, mode=jmode)
            jsonhandler.setLevel(jlevel)
            jsonhandler.setFormatter(NativeJsonFormatter())
            baselogger.addHandler(jsonhandler)

        self._logger = newlogger

        if len(initmsg) > 0:
            dst = logfilename if logfilename else "stderr"
            msg = initmsg + " with level: " + level + " to " + dst
            self._logger.info(msg)


chklogger = CHKLogger()
