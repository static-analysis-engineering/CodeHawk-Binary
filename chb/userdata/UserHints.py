#!/usr/bin/env python3
# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs, LLC
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
"""Converter for user hints from json to xml.

User data can be presented to the python front end in the form of dictionaries.
The data in these dictionaries are converted to xml to be read by the analyzer.
Each kind of user hint has its own structure on how the data is to be presented.
Some user hints may involve additional supporting files in the form of function
summaries or data structure definition files.

This module contains the classes for simple user hints that usually involve only
a few data items.

Currently provided:
- ArgumentConstraints:
      function arguments and global variables

- ARMThumbSwitchPoints
      addresses where ARM switches to Thumb-2 and v.v.

- DataBlocks
      pairs of addresses (start inclusive, end exclusive) that indicate data

- FunctionEntryPoints
      addresses of function entry points

- FunctionNames
      mapping of function entry points to function names

- IndirectJumps
      mapping of function/instr address to list of possible targets

- NonReturningCalls
      list of function/instr addresses with calls that do not return
      (intended for functions that may return in other calls)

- NonReturningFunctions
      list of addresses of functions that do not return
      (intended for functions that never return like exit and abort)

- SectionHeaders
      section header info
      (intended to supplement construction of section headers when these
      are not included in a binary)

- Successors
      map of instruction addresses to a range of successors

- SymbolicAddresses
      map of global-variable addresses to name/type info on the variable

"""

import json
import os
import xml.etree.ElementTree as ET

from abc import ABC, abstractmethod
from typing import Any, cast, Dict, List, Optional, Sequence, Tuple, Union

import chb.util.fileutil as UF
import chb.util.xmlutil as UX


class HintsEntry(ABC):

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @abstractmethod
    def update(self, d: Any) -> None:
        ...

    @abstractmethod
    def to_xml(self, node: ET.Element) -> None:
        ...

    def __str__(self) -> str:
        return self.name


class ARMArgumentConstraints(HintsEntry):
    """Mapping of registers to lower/upper bounds per function."""

    def __init__(self, argconstraints: Dict[str, Dict[str, Dict[str, int]]]) -> None:
        """Format: {fn -> {reg -> {offset: o, lb: x, ub: y}, .... } }

        use -deref ending to indicate offset field, rather than argument itself.

        Example: {"0x1000":
                     { "R0-deref": {"offset": 3,
                              "lb": 0,
                              "ub": 127},
                       "R1-deref": {offset": 2,
                              "v": 0} }}
        """

        HintsEntry.__init__(self, "arg-constraints")
        self._argconstraints = argconstraints

    @property
    def argconstraints(self) -> Dict[str, Dict[str, Dict[str, int]]]:
        return self._argconstraints

    def update(self, d: Dict[str, Dict[str, Dict[str, int]]]) -> None:
        """Only include new registers."""
        for fn in d:
            if fn in self._argconstraints:
                for r in d[fn]:
                    if r not in self._argconstraints[fn]:
                        self._argconstraints[fn][r] = d[fn][r]
            else:
                self._argconstraints[fn] = d[fn]

    def to_xml(self, node: ET.Element) -> None:
        xconstraints = ET.Element(self.name)
        node.append(xconstraints)
        for fn in self.argconstraints:
            xfn = ET.Element("fn")
            xconstraints.append(xfn)
            xfn.set("a", fn)
            for arg in self.argconstraints[fn]:
                xarg = ET.Element("c")
                argconstraint = self.argconstraints[fn][arg]
                xfn.append(xarg)
                if ":" in arg:
                    argname = arg.split(":")
                    xarg.set("n", argname[0])
                    xarg.set("offset", argname[1])
                else:
                    xarg.set("n", arg)
                if "lb" in argconstraint:
                    xarg.set("lb", str(argconstraint["lb"]))
                if "ub" in argconstraint:
                    xarg.set("ub", str(argconstraint["ub"]))
                if "v" in argconstraint:
                    xarg.set("v", str(argconstraint["v"]))

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Argument constraints")
        lines.append("--------------------")
        for fn in self.argconstraints:
            lines.append(fn)
            for arg in self.argconstraints[fn]:
                argconstraint = self.argconstraints[fn][arg]
                lines.append(
                    "  "
                    + arg
                    + " ".join(
                        k + ":" + str(v) for (k, v) in argconstraint.items()))
        return "\n".join(lines)


class ARMThumbSwitchPoints(HintsEntry):
    """List of addresses where arm switches to thumb or v.v."""

    def __init__(self, switchpoints: List[str]) -> None:
        """Format: [ hex:T or hex:A ]."""

        HintsEntry.__init__(self, "arm-thumb")
        self._switchpoints = switchpoints

    @property
    def switchpoints(self) -> List[str]:
        return self._switchpoints

    def update(self, d: List[str]) -> None:
        for p in d:
            if p not in self._switchpoints:
                self._switchpoints.append(p)

    def to_xml(self, node: ET.Element) -> None:
        xswitchpoints = ET.Element(self.name)
        node.append(xswitchpoints)
        for p in self.switchpoints:
            if p.endswith(":A") or p.endswith(":T"):
                iaddr = p[:-2]
                tgt = p[-1]
                xs = ET.Element("switch")
                xs.set("ia", iaddr)
                xs.set("tgt", tgt)
                xswitchpoints.append(xs)
            else:
                raise UF.CHBError(
                    "Error in thumb switch point: "
                    + "Expected format <addr>:A or <addr>:T . "
                    + "Found: " + p)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Arm-thumb switch points")
        lines.append("-----------------------")
        for p in self.switchpoints:
            lines.append("  " + p)
        return "\n".join(lines)


class DataBlocksHints(HintsEntry):
    """List of records with range and (optional) name of block."""

    def __init__(self, datablocks: List[Dict[str, Union[List[str], str]]]) -> None:
        """Format: {r:[start-addr, end-addr (exclusive)]}."""

        HintsEntry.__init__(self, "data-blocks")
        self._datablocks = datablocks
        self._addrs = [x["r"][0] for x in datablocks]

    @property
    def datablocks(self) -> List[Dict[str, Union[List[str], str]]]:
        return self._datablocks

    def has_start_address(self, addr: str) -> bool:
        return addr in self._addrs

    def update(self, d: List[Dict[str, Union[List[str], str]]]) -> None:
        for db in d:
            addr = cast(str, db["r"][0])
            if not self.has_start_address(addr):
                self._datablocks.append(db)
                self._addrs.append(addr)

    def to_xml(self, node: ET.Element) -> None:
        xdatablocks = ET.Element(self.name)
        node.append(xdatablocks)
        for db in sorted(self.datablocks, key=lambda r: r["r"[0]]):
            xdb = ET.Element("db")
            xdb.set("start", db["r"][0])
            xdb.set("end", db["r"][1])
            if "n" in db:
                dbname = cast(str, db["n"])
                xdb.set("name", dbname)
            xdatablocks.append(xdb)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Data blocks")
        lines.append("-----------")
        for db in self.datablocks:
            if "n" in db:
                dbname = cast(str, db["n"])
                dbname = " (" + dbname + ")"
            else:
                dbname = ""
            lines.append("  [" + db["r"][0] + ", " + db["r"][1] + dbname)
        return "\n".join(lines)


class FunctionEntryPointsHints(HintsEntry):
    """List of function entry points in hex."""

    def __init__(self, fepoints: List[str]) -> None:
        HintsEntry.__init__(self, "function-entry-points")
        self._entrypoints = fepoints

    @property
    def entrypoints(self) -> List[str]:
        return self._entrypoints

    def update(self, d: List[str]) -> None:
        for p in d:
            if p not in self._entrypoints:
                self._entrypoints.append(p)

    def to_xml(self, node: ET.Element) -> None:
        xfepoints = ET.Element(self.name)
        node.append(xfepoints)
        for a in self.entrypoints:
            xfe = ET.Element("fe")
            xfe.set("a", a)
            xfepoints.append(xfe)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Function entry points")
        lines.append("---------------------")
        for a in self.entrypoints:
            lines.append("  " + a)
        return "\n".join(lines)


class FunctionNamesHints(HintsEntry):
    """Mapping of function addresses to function names.

    Format:
       <function-address(hex)>: <function-name>
    """

    def __init__(self, fnames: Dict[str, str]) -> None:
        HintsEntry.__init__(self, "function-names")
        self._fnames = fnames

    @property
    def fnames(self) -> Dict[str, str]:
        return self._fnames

    def update(self, d: Dict[str, str]) -> None:
        for faddr in d:
            if faddr not in self._fnames:
                self._fnames[faddr] = d[faddr]

    def to_xml(self, node: ET.Element) -> None:
        xfnames = ET.Element(self.name)
        node.append(xfnames)
        for (faddr, fname) in sorted(self.fnames.items()):
            xfn = ET.Element("fn")
            xfnames.append(xfn)
            xfn.set("a", faddr)
            xfn.set("n", fname)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Function names")
        lines.append("--------------")
        for (faddr, fname) in sorted(self.fnames.items()):
            lines.append("  " + faddr.ljust(10) + ": " + fname)
        return "\n".join(lines)


class IndirectJumpsHints(HintsEntry):
    """List of records that specify the targets of an indirect jump.

    Format of record:
       "fa": <function address>,
       "ia": <address of jump-instruction>,
       "targets": [ <target addresses> ]
    """

    def __init__(self, jumps: List[Dict[str, Union[str, List[str]]]]) -> None:
        HintsEntry.__init__(self, "indirect-jumps")
        self._jumps = jumps
        self._locations: List[Tuple[str, str]] = []
        for x in self._jumps:
            if "fa" in x and "ia" in x:
                fa = cast(str, x["fa"])
                ia = cast(str, x["ia"])
                self._locations.append((fa, ia))
            else:
                raise UF.CHBError(
                    "Invalid record in indirect-jumps: fa or ia is missing")

    @property
    def jumps(self) -> List[Dict[str, Union[str, List[str]]]]:
        return self._jumps

    def update(self, d: List[Dict[str, Union[str, List[str]]]]) -> None:
        for r in d:
            if (r["fa"], r["ia"]) not in self._locations:
                self._jumps.append(r)
                fa = cast(str, r["fa"])
                ia = cast(str, r["ia"])
                self._locations.append((fa, ia))

    def to_xml(self, node: ET.Element) -> None:
        xjumps = ET.Element(self.name)
        node.append(xjumps)
        for r in self.jumps:
            if "fa" in r and "ia" in r and "targets" in r:
                fa = cast(str, r["fa"])
                ia = cast(str, r["ia"])
                tgts = cast(List[str], r["targets"])
                xj = ET.Element("jumpinstr")
                xjumps.append(xj)
                xj.set("fa", fa)
                xj.set("ia", ia)
                for tgt in tgts:
                    xtgt = ET.Element("tgt")
                    xj.append(xtgt)
                    xtgt.set("a", tgt)
            else:
                raise UF.CHBError(
                    "Invalid format for indirect jump: "
                    + "expected to find fa, ia, and targets")

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Indirect jumps")
        lines.append("--------------")
        for r in self.jumps:
            if "fa" in r and "ia" in r and "targets" in r:
                fa = cast(str, r["fa"])
                ia = cast(str, r["ia"])
                tgts = cast(List[str], r["targets"])
                lines.append("  [" + fa + ", " + ia + "]")
                lines.append("    " + ", ".join(tgts))
        return "\n".join(lines)


class NonReturningCallsHints(HintsEntry):
    """Call sites where the call does not return.

    Format:
       <function-address>: [ instruction-addresses ]
    """

    def __init__(self, nrcalls: Dict[str, List[str]]) -> None:
        HintsEntry.__init__(self, "non-returning-calls")
        self._nrcalls = nrcalls

    @property
    def nrcalls(self) -> Dict[str, List[str]]:
        return self._nrcalls

    def update(self, d: Dict[str, List[str]]) -> None:
        for faddr in d:
            if faddr in self._nrcalls:
                for iaddr in d[faddr]:
                    if iaddr not in self._nrcalls[faddr]:
                        self._nrcalls[faddr].append(iaddr)
            else:
                self._nrcalls[faddr] = d[faddr]

    def to_xml(self, node: ET.Element) -> None:
        xnrcalls = ET.Element(self.name)
        node.append(xnrcalls)
        for (faddr, iaddrs) in sorted(self.nrcalls.items()):
            for iaddr in iaddrs:
                xnr = ET.Element("nrc")
                xnrcalls.append(xnr)
                xnr.set("fa", faddr)
                xnr.set("ia", iaddr)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Non-return calls")
        lines.append("----------------")
        for (faddr, iaddrs) in sorted(self.nrcalls.items()):
            lines.append("  " + faddr + ": [" + ", ".join(iaddrs) + "]")
        return "\n".join(lines)


class NonReturningFunctionsHints(HintsEntry):
    """Addresses of functions that do not return (in hex)."""

    def __init__(self, nrfunctions: List[str]) -> None:
        HintsEntry.__init__(self, "non-returning-functions")
        self._nrfunctions = nrfunctions

    @property
    def nrfunctions(self) -> List[str]:
        return self._nrfunctions

    def update(self, d: List[str]) -> None:
        for faddr in d:
            if faddr not in self._nrfunctions:
                self._nrfunctions.append(faddr)

    def to_xml(self, node: ET.Element) -> None:
        xnrfunctions = ET.Element(self.name)
        node.append(xnrfunctions)
        for faddr in self.nrfunctions:
            xnr = ET.Element("nr")
            xnr.set("a", faddr)
            xnrfunctions.append(xnr)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Non-returning functions")
        lines.append("-----------------------")
        lines.append("  [" + ", ".join(sorted(self.nrfunctions)))
        return "\n".join(lines)


class SectionHeadersHints(HintsEntry):
    """Dictionary of section header information."""

    def __init__(self, shinfo: Dict[str, Dict[str, str]]) -> None:
        HintsEntry.__init__(self, "section-headers")
        self._shinfo = shinfo

    @property
    def section_header_info(self) -> Dict[str, Dict[str, str]]:
        return self._shinfo

    def update(self, shinfo: Dict[str, Dict[str, str]]) -> None:
        self._shinfo.update(shinfo)

    def to_xml(self, node: ET.Element) -> None:
        xshinfo = ET.Element(self.name)
        node.append(xshinfo)
        for (section, attrs) in self.section_header_info.items():
            xsh = ET.Element("sh")
            xshinfo.append(xsh)
            xsh.set("name", section)
            for (attr, attrvalue) in attrs.items():
                xfld = ET.Element("fld")
                xsh.append(xfld)
                xfld.set("name", attr)
                xfld.set("value", attrvalue)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Section header info")
        lines.append("-------------------")
        for (section, attrs) in self.section_header_info.items():
            lines.append("  " + section)
            for (attr, attrvalue) in attrs.items():
                lines.append("    " + attr + ": " + attrvalue)
        return "\n".join(lines)


class SuccessorsHints(HintsEntry):
    """Map of instruction addresses to a range of successors."""

    def __init__(self, successors: List[Dict[str, Union[List[str], str]]]) -> None:
        HintsEntry.__init__(self, "successors")
        self._successors = successors
        self._iaddrs: List[str] = [cast(str, x["ia"]) for x in successors]

    @property
    def successors(self) -> List[Dict[str, Union[List[str], str]]]:
        return self._successors

    def has_address(self, iaddr: str) -> bool:
        return iaddr in self._iaddrs

    def update(self, d: List[Dict[str, Union[List[str], str]]]) -> None:
        for srec in d:
            iaddr = cast(str, srec["ia"])
            if not self.has_address(iaddr):
                self._successors.append(srec)
                self._iaddrs.append(iaddr)

    def to_xml(self, node: ET.Element) -> None:
        xsuccessors = ET.Element(self.name)
        node.append(xsuccessors)
        for srec in self.successors:
            if "ia" in srec:
                iaddr = cast(str, srec["ia"])
                if "sr" in srec:
                    addrs: List[str] = []
                    srange = cast(List[str], srec["sr"])
                    sa = int(srange[0], 16)
                    se = int(srange[1], 16)
                    for a in range(sa, se, 4):
                        addrs.append(hex(a))
                    xs = ET.Element("instr")
                    xs.set("ia", iaddr)
                    xs.set("ss", ",".join(addrs))
                    xsuccessors.append(xs)
                else:
                    raise UF.CHBError(
                        "Successor range field missing "
                        + "from successor specification: "
                        + iaddr)
            else:
                raise UF.CHBError(
                    "Instruction address (ia) missing from successor specification")

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Instruction successors")
        lines.append("----------------------")
        for srec in self.successors:
            if "ia" in srec and "sr" in srec:
                iaddr = cast(str, srec["ia"])
                srange = cast(List[str], srec["sr"])
                lines.append("  iaddr: "
                             + iaddr
                             + ": ["
                             + ", ".join(srange)
                             + "]")
        return "\n".join(lines)


class SymbolicAddressesHints(HintsEntry):
    """Map of global variable addresses to name/type info on the variables.

    Format: { <gv-addr>: {"name": <name>, "type": <type-name>} }
    """

    def __init__(self, symbolicaddrs: Dict[str, Dict[str, str]]) -> None:
        HintsEntry.__init__(self, "symbolic-addresses")
        self._symbolicaddrs = symbolicaddrs

    @property
    def symbolicaddrs(self) -> Dict[str, Dict[str, str]]:
        return self._symbolicaddrs

    def update(self, d: Dict[str, Dict[str, str]]) -> None:
        for gv in d:
            self._symbolicaddrs[gv] = d[gv]

    def to_xml(self, node: ET.Element) -> None:
        xaddrs = ET.Element(self.name)
        node.append(xaddrs)
        for (gv, gvinfo) in self.symbolicaddrs.items():
            if "name" in gvinfo and "type" in gvinfo:
                xgv = ET.Element("syma")
                xaddrs.append(xgv)
                xgv.set("a", gv)
                gvname = cast(str, gvinfo["name"])
                gvtype = cast(str, gvinfo["type"])
                xgv.set("name", gvname)
                xgv.set("type", gvtype)
            else:
                raise UF.CHBError(
                    "Name of type missing from symbolic address: "
                    + gv)

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Symbolic addresses")
        lines.append("------------------")
        for (gv, gvinfo) in self.symbolicaddrs.items():
            if "name" in gvinfo and "type" in gvinfo:
                gvname = cast(str, gvinfo["name"])
                gvtype = cast(str, gvinfo["type"])
                lines.append(gv + ": " + gvname + " (" + gvtype + ")")
        return "\n".join(lines)


class UserHints:

    def __init__(self) -> None:
        self.userdata: Dict[str, HintsEntry] = {}

    def add_hints(self, hints: Dict[str, Any]) -> None:
        """Process a user provided dictionary with user hint dictionaries.

        Currently supported:
        - arm-thumb (switchpoints)
        - data-blocks
        - function-entry-points
        - non-returning-functions
        - section-headers
        - successors
        """

        if "arg-constraints" in hints:
            tag = "arg-constraints"
            argconstraints: Dict[str, Dict[str, Dict[str, int]]] = hints[tag]
            if tag in self.userdata:
                self.userdata[tag].update(argconstraints)
            else:
                self.userdata[tag] = ARMArgumentConstraints(argconstraints)

        if "arm-thumb" in hints:
            tag = "arm-thumb"
            switchpoints: List[str] = hints[tag]
            if tag in self.userdata:
                self.userdata[tag].update(switchpoints)
            else:
                self.userdata[tag] = ARMThumbSwitchPoints(switchpoints)

        if "data-blocks" in hints:
            tag = "data-blocks"
            datablocks: List[Dict[str, Union[List[str], str]]] = hints[tag]
            if tag in self.userdata:
                self.userdata[tag].update(datablocks)
            else:
                self.userdata[tag] = DataBlocksHints(datablocks)

        if "function-entry-points" in hints:
            tag = "function-entry-points"
            fepoints: List[str] = hints[tag]
            if tag in self.userdata:
                self.userdata[tag].update(fepoints)
            else:
                self.userdata[tag] = FunctionEntryPointsHints(fepoints)

        if "function-names" in hints:
            tag = "function-names"
            fnames: Dict[str, str] = hints[tag]
            if tag in self.userdata:
                self.userdata[tag].update(fnames)
            else:
                self.userdata[tag] = FunctionNamesHints(fnames)

        if "indirect-jumps" in hints:
            tag = "indirect-jumps"
            jumps: List[Dict[str, Any]] = hints["indirect-jumps"]
            if tag in self.userdata:
                self.userdata[tag].update(jumps)
            else:
                self.userdata[tag] = IndirectJumpsHints(jumps)

        if "non-returning-calls" in hints:
            tag = "non-returning-calls"
            nrcalls: Dict[str, List[str]] = hints[tag]
            if tag in self.userdata:
                self.userdata[tag].update(nrcalls)
            else:
                self.userdata[tag] = NonReturningCallsHints(nrcalls)

        if "non-returning-functions" in hints:
            tag = "non-returning-functions"
            nrfunctions: List[str] = hints[tag]
            if tag in self.userdata:
                self.userdata[tag].update(nrfunctions)
            else:
                self.userdata[tag] = NonReturningFunctionsHints(nrfunctions)

        if "section-headers" in hints:
            tag = "section-headers"
            sectionheaders: Dict[str, Dict[str, str]] = hints[tag]
            if tag in self.userdata:
                self.userdata[tag].update(sectionheaders)
            else:
                self.userdata[tag] = SectionHeadersHints(sectionheaders)

        if "successors" in hints:
            tag = "successors"
            successors: List[Dict[str, Union[List[str], str]]] = hints[tag]
            if tag in self.userdata:
                self.userdata[tag].update(successors)
            else:
                self.userdata[tag] = SuccessorsHints(successors)

        if "symbolic-addresses" in hints:
            tag = "symbolic-addresses"
            symbolicaddrs: Dict[str, Dict[str, str]] = hints[tag]
            if tag in self.userdata:
                self.userdata[tag].update(symbolicaddrs)
            else:
                self.userdata[tag] = SymbolicAddressesHints(symbolicaddrs)

    def to_xml(self, filename: str) -> ET.ElementTree:
        root = UX.get_codehawk_xml_header(filename, "system-userdata")
        tree = ET.ElementTree(root)
        snode = ET.Element("system-info")
        root.append(snode)
        for tag in sorted(self.userdata):
            self.userdata[tag].to_xml(snode)
        return tree

    def __str__(self) -> str:
        lines: List[str] = []
        for tag in sorted(self.userdata):
            lines.append(str(self.userdata[tag]))
            lines.append("")
        return "\n".join(lines)
