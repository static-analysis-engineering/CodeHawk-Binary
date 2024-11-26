# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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

import xml.etree.ElementTree as ET

from typing import Dict, List, Mapping, Optional, Sequence, Tuple

import chb.util.fileutil as UF


class CallbackTableRecord:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode
        self._fields: Dict[int, Tuple[str, str]] = {}

    @property
    def fields(self) -> Mapping[int, Tuple[str, str]]:
        if len(self._fields) == 0:
            for x in self.xnode.findall("v"):
                offset = x.get("offset")
                tag = x.get("tag")
                value = x.get("value")
                if (
                        offset is not None
                        and tag is not None
                        and value is not None):
                    self._fields[int(offset)] = (tag, value)
        return self._fields

    @property
    def structure(self) -> Mapping[int, str]:
        result: Dict[int, str] = {}
        for (offset, (tag, value)) in self.fields.items():
            result[offset] = tag
        return result

    @property
    def function_pointers(self) -> List[str]:
        result: List[str] = []
        for (tag, value) in self.fields.values():
            if tag == "address":
                result.append(value)
        return result

    @property
    def tag_offset(self) -> int:
        """Return the offset of the first field with type tag."""

        for (offset, (tag, value)) in self.fields.items():
            if tag == "tag":
                return offset

        return (-1)

    @property
    def tag(self) -> Optional[str]:
        if self.tag_offset >= 0:
            return self.fields[self.tag_offset][1]
        else:
            return None

    def value_at_offset(self, offset: int) -> str:
        if offset in self.fields:
            return self.fields[offset][1]
        else:
            return "0x0"

    def serialize(self) -> Dict[int, str]:
        result: Dict[int, str] = {}
        for f in self.fields:
            result[f] = self.fields[f][1]
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        for (offset, (tag, value)) in sorted(self.fields.items()):
            lines.append(str(offset).rjust(3) + ": " + tag.ljust(10) + value)
        return "\n".join(lines)


class CallbackTable:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode
        self._records: List[CallbackTableRecord] = []

    @property
    def records(self) -> Sequence[CallbackTableRecord]:
        if len(self._records) == 0:
            for x in self.xnode.findall("cbr"):
                address = x.get("address")
                if address is not None:
                    self._records.append(CallbackTableRecord(x))
        return self._records

    @property
    def structure(self) -> Mapping[int, str]:
        if len(self.records) > 0:
            return self.records[0].structure
        else:
            return {}

    def tagged_fields_at_offset(self, offset: int) -> Dict[str, str]:
        result: Dict[str, str] = {}
        counter = 0
        for r in self.records:
            counter += 1
            tag = r.tag
            if tag is None:
                tag = str(counter)
            result[tag] = r.value_at_offset(offset)
        return result

    def tags(self) -> List[str]:
        result: List[str] = []
        if len(self.records) > 0:
            tagoffset = self.records[0].tag_offset
            if tagoffset >= 0:
                for r in self.records:
                    result.append(r.value_at_offset(tagoffset))
        return result

    def serialize(self) -> List[Dict[int, str]]:
        return [r.serialize() for r in self.records]

    def __str__(self) -> str:
        lines: List[str] = []
        for r in self.records:
            lines.append(str(r))
            lines.append("")
        return "\n".join(lines)


class CallbackTables:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode
        self._tables: Dict[str, CallbackTable] = {}

    @property
    def callbacktables(self) -> Dict[str, CallbackTable]:
        if len(self._tables) == 0:
            for x in self.xnode.findall("call-back-table"):
                address = x.get("address")
                if address is not None:
                    self._tables[address] = CallbackTable(x)
        return self._tables

    def callbacktable(self, address: str) -> CallbackTable:
        if address in self.callbacktables:
            return self.callbacktables[address]
        else:
            raise UF.CHBError("No callback table found at address " + address)

    def __str__(self) -> str:
        lines: List[str] = []
        for (address, table) in sorted(self.callbacktables.items()):
            lines.append("-" * 80)
            lines.append("table location: " + address)
            lines.append(str(table))
            lines.append("=" * 80)
            lines.append("")
        return "\n".join(lines)
