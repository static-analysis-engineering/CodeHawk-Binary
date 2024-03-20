# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2024  Aarno Labs LLC
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

from chb.app.CHVersion import chbversion

from chb.jsoninterface.JSONResult import JSONResult
from chb.jsoninterface.JSONSchema import JSONSchema

from chb.relational.BlockRelationalAnalysis import BlockRelationalAnalysis

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger, LogLevel


if TYPE_CHECKING:
    from chb.app.BasicBlock import BasicBlock
    from chb.app.Function import Function
    from chb.cmdline.XInfo import XInfo
    from chb.invariants.InvariantFact import InvariantFact
    from chb.relational.FunctionRelationalAnalysis import FunctionRelationalAnalysis


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
    jmeta["version"] = chbversion
    return jresult


def jsonok(schemaname: str, content: Dict[str, Any]) -> Dict[str, Any]:
    jresult: Dict[str, Any] = {}
    jresult["meta"] = jmeta = {}
    jmeta["status"] = "ok"
    (jmeta["date"], jmeta["time"]) = jsondate()
    jmeta["schema"] = schemaname
    jmeta["version"] = chbversion
    jresult["content"] = content
    return jresult


def jsonappdata(xinfo: "XInfo") -> Dict[str, str]:
    result: Dict[str, str] = {}
    result["path"] = xinfo.path
    result["file"] = xinfo.file
    result["md5"] = xinfo.md5
    result["arch"] = xinfo.architecture
    return result


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


def cfg_edge_to_json_result(
        f: "Function", src: str, tgt: str, kind: str) -> JSONResult:
    content: Dict[str, Any] = {}
    content["src"] = src
    content["tgt"] = tgt
    content["kind"] = kind
    if kind in ["true", "false"]:
        if src in f.branchconditions:
            branchinstr = f.branchconditions[src]
            ftconds = branchinstr.ft_conditions
            if len(ftconds) == 2:
                if kind == "true":
                    pred = ftconds[1].to_json_result()
                else:
                    pred = ftconds[0].to_json_result()
                if not pred.is_ok:
                    return JSONResult("cfgedge", {}, "fail", pred.reason)
                else:
                    content["predicate"] = pred.content
    return JSONResult("cfgedge", content, "ok")


def cfg_node_to_json_result(f: "Function", b: "BasicBlock") -> JSONResult:
    content: Dict[str, Any] = {}
    content["id"] = b.baddr
    content["baddr"] = b.real_baddr
    bresult = b.to_json_result()
    if not bresult.is_ok:
        return JSONResult("cfgnode", {}, "fail", bresult.reason)
    else:
        content["code"] = bresult.content
        if b.baddr in f.cfg.blocks:
            looplevels = f.cfg.loop_levels(b.baddr)
            if len(looplevels) > 0:
                content["nesting-level"] = len(looplevels)
    return JSONResult("cfgnode", content, "ok")


def function_cfg_to_json_result(f: "Function") -> JSONResult:
    content: Dict[str, Any] = {}
    content["faddr"] = f.faddr
    if len(f.names) > 0:
        content["name"] = f.names[0]
    content["md5hash"] = f.md5
    content["nodes"] = nodes = []
    content["edges"] = edges = []
    for b in f.blocks.values():
        bnode = cfg_node_to_json_result(f, b)
        if not bnode.is_ok:
            return JSONResult("controlflowgraph", {}, "fail", bnode.reason)
        else:
            nodes.append(bnode.content)
    for (src, tgts) in f.cfg.edges.items():
        if len(tgts) == 1:
            edge = cfg_edge_to_json_result(f, src, tgts[0], "single")
            if not edge.is_ok:
                return JSONResult("controlflowgraph", {}, "fail", edge.reason)
            else:
                edges.append(edge.content)
        elif len(tgts) == 2:
            f_edge = cfg_edge_to_json_result(f, src, tgts[0], "false")
            if not f_edge.is_ok:
                return JSONResult("controlflowgraph", {}, "fail", f_edge.reason)
            t_edge = cfg_edge_to_json_result(f, src, tgts[1], "true")
            if not t_edge.is_ok:
                return JSONResult("controlflowgraph", {}, "fail", t_edge.reason)
            edges.extend([f_edge.content, t_edge.content])
        else:
            for tgt in tgts:
                edge = cfg_edge_to_json_result(f, src, tgt, "table")
                if not edge.is_ok:
                    return JSONResult("controlflowgraph", {}, "fail", edge.reason)
                edges.append(edge.content)

    return JSONResult("controlflowgraph", content, "ok")
