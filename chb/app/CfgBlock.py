# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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
"""Abstract superclass of control flow graph basic block of function.

Subclasses:
 - ARMCfgBlock
 - MIPSCfgBlock
"""

import xml.etree.ElementTree as ET

import chb.util.fileutil as UF

from typing import Dict, List, Optional


class CfgBlock:

    def __init__(
            self,
            xnode: ET.Element) -> None:
        self.xnode = xnode

    @property
    def firstaddr(self) -> str:
        a = self.xnode.get("ba")
        if a is None:
            raise UF.CHBError("Block address missing in cfg block")
        return a

    @property
    def lastaddr(self) -> str:
        a = self.xnode.get("ea")
        if a is None:
            raise UF.CHBError("Block end address missing in cfg block")
        return a

    @property
    def looplevels(self) -> List[str]:
        xloops = self.xnode.find("loops")
        if xloops is None:
            return []
        else:
            result: List[str] = []
            for i in xloops.findall("lv"):
                a = i.get("a")
                if a is None:
                    raise UF.CHBError("Address missing from loop level")
                result.append(a)
            return result

    @property
    def in_loop(self) -> bool:
        return len(self.looplevels) > 0

    @property
    def role(self) -> Optional[str]:
        return self.xnode.get("role")

    @property
    def is_in_trampoline(self) -> bool:
        if self.role is not None:
            return self.role.startswith("trampoline")
        else:
            return False

    @property
    def is_trampoline(self) -> bool:
        return False

    @property
    def roles(self) -> Dict[str, str]:
        return {}
