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
"""Converter for user hints from json to xml."""

import json
import os
import xml.etree.ElementTree as ET

import chb.util.fileutil as UF
import chb.util.xmlutil as UX

from typing import Any, Dict, List, Union


class UserHints:

    def __init__(self, filenames: List[str]) -> None:
        self.filenames = filenames
        self.userhints: Dict[str, Any] = {}
        self._initialize()

    def add_hints(self, hints: Dict[str, Any]) -> None:
        if "data-blocks" in hints:
            self.add_data_blocks(hints["data-blocks"])
        if "function-entry-points" in hints:
            self.add_function_entry_points(hints["function-entry-points"])
        if "successors" in hints:
            self.add_successors(hints["successors"])

    def add_data_blocks(
            self,
            hints: List[Dict[str, Union[List[str], str]]]) -> None:
        """List of records:

        {r:[start-addr, end-addr (exclusive)], t: jumptable (optional)}."""
        self.userhints.setdefault("data-blocks", {})
        for r in hints:
            if ("r" not in r):
                raise UF.CHBError("Encountered data-block record without r field")
            if (not len(r["r"]) == 2):
                raise UF.CHBError("Expected two elements in data-block record")
            startaddr = int(r["r"][0], 16)
            endaddr = int(r["r"][1], 16)
            if startaddr >= endaddr:
                raise UF.CHBError(
                    "Start is larger than end address: "
                    + hex(startaddr)
                    + ", "
                    + hex(endaddr))
            self.userhints["data-blocks"][r["r"][0]] = r

    def add_function_entry_points(
            self,
            hints: List[Dict[str, Union[List[str], str]]]) -> None:
        """List of records:

        { a: addr, n: name (optional), p: [ "nr" ] (optional) }. """
        self.userhints.setdefault("function-entry-points", {})
        for r in hints:
            if ("a" not in r):
                raise UF.CHBError("Encountered function-entry without a field")
            self.userhints["function-entry-points"][r["a"]] = r

    def add_successors(self, hints: List[Dict[str, Any]]) -> None:
        self.userhints.setdefault("successors", {})
        for r in hints:
            if ("ia" not in r):
                raise UF.CHBError(
                    "Encountered successors record without instruction address ia")
            if "sr" in r:
                addrs: List[str] = []
                sa = int(r["sr"][0], 16)
                se = int(r["sr"][1], 16)
                for a in range(sa, se, 4):
                    addrs.append(hex(a))
                self.userhints["successors"][r["ia"]] = addrs

    def add_xml_data_blocks(self, snode: ET.Element) -> None:
        if "data-blocks" in self.userhints:
            datablocks = ET.Element("data-blocks")
            snode.append(datablocks)
            for a in self.userhints["data-blocks"]:
                db = self.userhints["data-blocks"][a]
                xdb = ET.Element("db")
                xdb.set("start", db["r"][0])
                xdb.set("end", db["r"][1])
                datablocks.append(xdb)

    def add_xml_function_entry_points(self, snode: ET.Element) -> None:
        if "function-entry-points" in self.userhints:
            fepoints = ET.Element("function-entry-points")
            fnames = ET.Element("function-names")
            snode.append(fepoints)
            snode.append(fnames)
            for a in self.userhints["function-entry-points"]:
                fe = self.userhints["function-entry-points"][a]
                xfe = ET.Element("fe")
                xfe.set("a", fe["a"])
                fepoints.append(xfe)
                if "n" in fe:
                    xfn = ET.Element("fn")
                    xfn.set("a", fe["a"])
                    xfn.set("n", fe["n"])
                    fnames.append(xfn)

    def add_xml_successors(self, snode: ET.Element) -> None:
        if "successors" in self.userhints:
            xsucc = ET.Element("successors")
            snode.append(xsucc)
            for ia in self.userhints["successors"]:
                xss = ET.Element("instr")
                xss.set("ia", ia)
                xss.set("ss", ",".join(self.userhints["successors"][ia]))
                xsucc.append(xss)

    def to_xml(self, filename: str) -> ET.ElementTree:
        root = UX.get_codehawk_xml_header(filename, "system-userdata")
        tree = ET.ElementTree(root)
        snode = ET.Element("system-info")
        root.append(snode)
        self.add_xml_data_blocks(snode)
        self.add_xml_function_entry_points(snode)
        self.add_xml_successors(snode)
        return tree

    def _initialize(self) -> None:
        for f in self.filenames:
            if os.path.isfile(f):
                with open(f, "r") as fp:
                    hints = json.load(fp)
                self.add_hints(hints)
