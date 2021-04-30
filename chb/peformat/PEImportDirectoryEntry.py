# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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

from typing import Any, Dict, List, TYPE_CHECKING

import chb.util.fileutil as UF

import chb.peformat.PEImportDirectoryNameEntry as E

if TYPE_CHECKING:
    import chb.peformat.PEHeader


class PEImportDirectoryEntry:
    """Represents an import table."""

    def __init__(
            self,
            peheader: "chb.peformat.PEHeader.PEHeader",
            xnode: ET.Element) -> None:
        self.peheader = peheader
        self.xnode = xnode

    @property
    def dllname(self) -> str:
        xname = self.xnode.get("dll-name")
        if xname:
            return xname
        else:
            raise UF.CHBError("Dll-name missing from import directory entry")

    @property
    def forwarder_chain(self) -> str:
        xchain = self.xnode.get("forwarder-chain")
        if xchain:
            return xchain
        else:
            raise UF.CHBError(
                "Forwarder chain missing from import directory entry")

    @property
    def imported_address_table_rva(self) -> str:
        xtable = self.xnode.get("import-address-table-rva")
        if xtable:
            return xtable
        else:
            raise UF.CHBError(
                "Import address table rva missing from import directory entry")

    @property
    def import_lookup_table_rva(self) -> str:
        xtable = self.xnode.get("import-lookup-table-rva")
        if xtable:
            return xtable
        else:
            raise UF.CHBError(
                "Import lookup table rva missing from import directory entry")

    @property
    def name_rva(self) -> str:
        xname = self.xnode.get("name-rva")
        if xname:
            return xname
        else:
            raise UF.CHBError(
                "Name-rva missing from import directory entry")

    @property
    def timestamp(self) -> str:
        xdw = self.xnode.get("timestamp-dw")
        if xdw:
            return xdw
        else:
            raise UF.CHBError(
                "Timestamp is missing from import directory entry")

    @property
    def hint_name_table(self) -> ET.Element:
        xtable = self.xnode.find("hint-name-table")
        if xtable:
            return xtable
        else:
            raise UF.CHBError(
                "Hint-name-table missing from import directory entry")

    @property
    def name_entries(self) -> List[E.PEImportDirectoryNameEntry]:
        result: List[E.PEImportDirectoryNameEntry] = []
        for n in self.hint_name_table.findall("hint-name-entry"):
            result.append(E.PEImportDirectoryNameEntry(self, n))
        return sorted(result, key=lambda n: n.name)

    def has_summary(self, name: str) -> bool:
        return self.peheader.models.has_dll_function_summary(self.dllname, name)

    def as_dictionary(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        result["name"] = self.dllname
        result["entries"] = {}
        for n in self.name_entries:
            result["entries"][n.name] = n.as_dictionary
        return result

    def __str__(self) -> str:
        lines: List[str] = []

        def addline(tag: str, value: str) -> None:
            lines.append(tag.ljust(32) + ": " + value)

        lines.append("-" * 60)
        lines.append("Import table for " + self.dllname)
        lines.append("-" * 60)
        for n in self.name_entries:
            lines.append(str(n))
        return "\n".join(lines)
