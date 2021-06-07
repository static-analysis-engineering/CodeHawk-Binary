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

from typing import Generator, List, Tuple, TYPE_CHECKING

import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.app.Instruction
    import chb.peformat.PEHeader


class PESection:
    """Provides access to the raw data in a PE section."""

    def __init__(
            self,
            peheader: "chb.peformat.PEHeader.PEHeader",
            xnode: ET.Element) -> None:
        self._peheader = peheader
        self.xnode = xnode

    @property
    def size(self) -> int:
        xsize = self.xnode.get("size")
        if xsize:
            return int(xsize, 16)
        else:
            raise UF.CHBError("Raw section does not have a size")

    @property
    def virtual_address(self) -> str:
        xva = self.xnode.get("va")
        if xva:
            return xva
        else:
            raise UF.CHBError("Raw section does not have a virtual address")

    @property
    def block_count(self) -> int:
        xhexdata = self.xnode.find("hex-data")
        if xhexdata:
            xblocks = xhexdata.get("blocks")
            if xblocks:
                return int(xblocks)
            else:
                raise UF.CHBError(
                    "Raw section hex-data does not have a blocks attribute")
        else:
            raise UF.CHBError(
                "Raw section does not have a hex-data element")

    @property
    def hex_data(self) -> ET.Element:
        xhexdata = self.xnode.find("hex-data")
        if xhexdata:
            return xhexdata
        else:
            raise UF.CHBError("Raw section without hex-data")

    def get_strings(self, minlen: int = 3) -> Generator[
            Tuple[int, List[int]], None, None]:
        """Yield sequences of printable characters of mimimum length minlen."""
        def makestream(s: str) -> Generator[Tuple[int, int], None, None]:
            c = 0
            for w in s.split():
                for i in range(0, len(w), 2):
                    yield((c*8) + i, int(w[i:i+2], 16))
                c += 1

        def is_printable(i: int) -> bool:
            return (i >= 32 and i < 127)

        result: List[int] = []
        for b in self.hex_data.findall("ablock"):
            for a in b.findall("aline"):
                xva = a.get("va")
                if xva:
                    va = int(xva, 16)
                    xbytes = a.get("bytes")
                    if xbytes:
                        for (offset, i) in makestream(xbytes):
                            if is_printable(i):
                                result.append(i)
                            else:
                                if len(result) >= minlen:
                                    strva = (va + (offset // 2)) - len(result)
                                    strval = result[:]
                                    result = []
                                    yield (strva, strval)
                                else:
                                    result = []
                    else:
                        raise UF.CHBError(
                            "Raw section line without bytes")
                else:
                    raise UF.CHBError("Raw section line without virtual address")

    def get_zero_blocks(self, hexva: str, align: int = 32) -> List[Tuple[str, str]]:
        s = ""
        offsetalign = 2 * align
        z = "0" * offsetalign
        qalign = int(align / 4)
        qoffsetalign = int(offsetalign / 4)
        qz = "0" * qoffsetalign
        for b in self.hex_data.findall("block"):
            for a in b.findall("aline"):
                xbytes = a.get("bytes")
                if xbytes:
                    s += xbytes.replace(" ", "")
                else:
                    raise UF.CHBError("Raw section line without bytes")
        va = int(hexva, 16)
        offset = 0
        slen = len(s)
        result = []
        while (va % align) > 0:
            va += 1
            offset += 2
        while offset < slen - offsetalign:
            while s[offset:offset+offsetalign] != z:
                va += align
                offset += offsetalign
                if offset > slen - offsetalign:
                    break
            if offset > slen - qoffsetalign:
                break
            dbstart = hex(va)
            while (s[offset:offset+qoffsetalign] == qz):
                va += qalign
                offset += qoffsetalign
                if offset > slen - qoffsetalign:
                    break
            dbend = hex(va)
            result.append((dbstart, dbend))
        return result

    def __str__(self) -> str:
        lines = []
        lines.append("-" * 80)
        lines.append("Section at "
                     + self.virtual_address
                     + " (size: "
                     + str(self.size)
                     + ')')
        lines.append("-" * 80)

        for b in self.hex_data.findall("ablock"):
            for line in b.findall("aline"):
                xva = line.get("va")
                xbytes = line.get("bytes")
                xprint = line.get("print")
                if xva and xbytes and xprint:
                    lines.append(xva
                                 + '    '
                                 + xbytes.ljust(40)
                                 + xprint)
                else:
                    raise UF.CHBError(
                        "Raw section line without va, bytes, or print")
        lines.append("=" * 80)
        return "\n".join(lines)
