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

from typing import Dict, List, Optional, TYPE_CHECKING

import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.models.SummaryCollection


class DllEnumValue:
    """A named constant that belongs to a particular type."""

    def __init__(self, typename: str, xnode: ET.Element) -> None:
        self._typename = typename
        self.xnode = xnode

    @property
    def is_constant(self) -> bool:
        return True

    @property
    def is_flag(self) -> bool:
        return False

    @property
    def typename(self) -> str:
        return self._typename

    @property
    def name(self) -> str:
        xname = self.xnode.get("name")
        if xname:
            return xname
        raise UF.CHBError("Dll enum value without name in " + self.typename)

    @property
    def value(self) -> int:
        xvalue = self.xnode.get("value")
        if xvalue:
            if xvalue.startswith("0x"):
                return int(xvalue, 16)
            else:
                return int(xvalue)
        else:
            raise UF.CHBError("Dll enum name without value " + self.typename)

    def __str__(self) -> str:
        return self.name + ": " + str(self.value)


class DllEnumFlagValue(DllEnumValue):

    def __init__(self, typename: str, xnode: ET.Element) -> None:
        DllEnumValue.__init__(self, typename, xnode)

    @property
    def value(self) -> int:
        xvalue = self.xnode.get("value")
        if xvalue:
            return int(xvalue, 16)
        raise UF.CHBError("Dll enum name without value " + self.typename)

    @property
    def is_constant(self) -> bool:
        return False

    @property
    def is_flag(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.name + ": " + hex(self.value)


class DllEnumDefinitions:
    """Definition of named enum values for a particular named type."""

    def __init__(self,
                 summarycollection: "chb.models.SummaryCollection.SummaryCollection",
                 typename: str,
                 xnode: ET.Element) -> None:
        self._typename = typename
        self.summarycollection = summarycollection
        self.xnode = xnode
        self._constants: Dict[str, DllEnumValue] = {}
        self._values: Dict[int, str] = {}

    @property
    def typename(self) -> str:
        return self._typename

    @property
    def constants(self) -> Dict[str, DllEnumValue]:
        if len(self._constants) == 0:
            xvalues = self.xnode.find("values")
            if xvalues:
                for xc in xvalues.findall("symc"):
                    symc = DllEnumValue(self.typename, xc)
                    self._constants[symc.name] = symc
                for xf in xvalues.findall("symf"):
                    symf = DllEnumFlagValue(self.typename, xf)
                    self._constants[symf.name] = symf
        return self._constants

    @property
    def names(self) -> List[str]:
        return sorted(self.constants.keys())

    @property
    def values(self) -> List[int]:
        return sorted([self.constants[c].value for c in self.constants])

    def has_name(self, v: int) -> bool:
        if v in self._values:
            return True
        else:
            for c in self.constants.values():
                if c.value == v:
                    self._values[v] = c.name
                    return True
                else:
                    self._values[c.value] = c.name
            else:
                return False

    def get_name(self, v: int) -> str:
        if self.has_name(v):
            return self._values[v]
        else:
            raise UF.CHBError("No name found in "
                              + self.typename
                              + "for value "
                              + str(v))

    def __str__(self) -> str:
        lines: List[str] = []
        maxlen = max(len(n) for n in self.names)
        for c in sorted(self.constants.values(), key=lambda d: d.name):
            cvalue = str(c.value) if c.is_constant else hex(c.value)
            lines.append(c.name.ljust(maxlen) + '  ' + cvalue.rjust(10))
        return '\n'.join(lines)
