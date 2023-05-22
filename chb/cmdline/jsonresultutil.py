# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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

import datetime

from typing import (
    Any, Dict, List, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING)

from chb.jsoninterface.JSONResult import JSONResult
from chb.jsoninterface.JSONSchema import JSONSchema

if TYPE_CHECKING:
    from chb.invariants.InvariantFact import InvariantFact


def jsondate() -> Tuple[str, str]:
    currenttime = datetime.datetime.now()
    cdate = currenttime.strftime("%Y-%m-%d")
    ctime = currenttime.strftime("%H:%M:%S")
    return (cdate, ctime)


def jsonfail(msg: Optional[str]) -> Dict[str, Any]:
    jresult: Dict[str, Any] = {}
    jresult["meta"] = jmeta = {}
    jmeta["status"] = "fail"
    jmeta["reason"] = str(msg)
    (jmeta["date"], jmeta["time"]) = jsondate()
    return jresult


def jsonok(fschema: JSONSchema, content: Dict[str, Any]) -> Dict[str, Any]:
    jresult: Dict[str, Any] = {}
    jresult["meta"] = jmeta = {}
    jmeta["status"] = "ok"
    (jmeta["date"], jmeta["time"]) = jsondate()
    jresult["schema"] = schema = fschema.base_schema
    if len(fschema.defs) > 0:
        schema["$defs"] = fschema.defs
    jresult["content"] = content
    return jresult


def location_invariant_to_json_result(
        loc: str, facts: Sequence["InvariantFact"]) -> JSONResult:
    content: Dict[str, Any] = {}
    content["location"] = loc
    ifacts: List[Dict[str, Any]] = []
    for f in facts:
        fresult = f.to_json_result()
        if fresult.is_ok:
            ifacts.append(fresult.content)
        else:
            return JSONResult(
                "locationinvariant",
                {},
                "fail",
                "locationinvariant: " + str(fresult.reason))
    content["invariants"] = ifacts
    return JSONResult("locationinvariant", content, "ok")


def function_invariants_to_json_result(
        invariants: Mapping[str, Sequence["InvariantFact"]]) -> JSONResult:
    ilocs: List[Dict[str, Any]] = []
    for (loc, invs) in invariants.items():
        locresult = location_invariant_to_json_result(loc, invs)
        if locresult.is_ok:
            ilocs.append(locresult.content)
        else:
            return JSONResult(
                "functioninvariants",
                {},
                "fail",
                "functioninvariants: " + str(locresult.reason))
    content: Dict[str, Any] = {}
    content["invariants"] = ilocs
    return JSONResult("functioninvariants", content, "ok")
