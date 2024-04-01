# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2024 Aarno Labs LLC
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

from typing import Dict, List, TYPE_CHECKING

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger

if TYPE_CHECKING:
    from chb.peformat.PEImportDirectoryEntry import PEImportDirectoryEntry


class PEImportDirectoryNameEntry():
    """Represents a single entry in an import table"""

    def __init__(
            self,
            peimporttable: "PEImportDirectoryEntry",
            xnode: ET.Element) -> None:
        self.peimporttable = peimporttable
        self.xnode = xnode

    @property
    def address(self) -> str:
        xaddr = self.xnode.get("bound-address")
        if xaddr is not None:
            return xaddr
        else:
            raise UF.CHBError(
                "No bound-address found in PEImportDirectoryNameEntry")

    @property
    def hint(self) -> str:
        xhint = self.xnode.get("hint")
        if xhint is not None:
            return xhint
        else:
            raise UF.CHBError("No hint found in PEImportDirectoryNameEntry")

    @property
    def name(self) -> str:
        xname = self.xnode.get("name")
        if xname is not None:
            if xname == "":
                chklogger.logger.warning(
                    "Empty name in PEImporDirectorNameEntry for address: "
                    + self.address + " (hint: " + str(self.hint) + ")")
            return xname
        else:
            raise UF.CHBError("No name found in PEImportDirectoryNameEntry")

    @property
    def rva(self) -> str:
        xrva = self.xnode.get("rva")
        if xrva is not None:
            return xrva
        else:
            raise UF.CHBError("No rva found in PEImportDirectoryNameEntry")

    @property
    def has_summary(self) -> bool:
        return self.peimporttable.has_summary(self.name)

    @property
    def as_dictionary(self) -> Dict[str, str]:
        result = {
            "name": self.name,
            "hint": self.hint,
            "address": self.address,
            "rva": self.rva,
            "summary": "Y" if self.has_summary else "N"
            }
        return result

    def __str__(self) -> str:
        summary = " "
        if self.has_summary:
            summary = "Y"
        hint = self.hint
        if hint is None:
            hint = " "
        return ((" " * 3)
                + hint.rjust(4)
                + "  "
                + self.address
                + "  "
                + summary
                + "  "
                + self.name)
