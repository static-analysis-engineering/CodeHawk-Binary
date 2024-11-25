# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024 Aarno Labs LLC
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
"""List of application function addresses and cfg characteristics."""

import xml.etree.ElementTree as ET

from typing import Dict, List, Optional


class FnCfgInfo:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode

    @property
    def faddr(self) -> str:
        return self.xnode.get("va", "0")

    @property
    def faddr_i(self) -> int:
        return int(self.xnode.get("va", "0"), 16)

    @property
    def basic_blocks(self) -> int:
        return int(self.xnode.get("bc", "0"))

    @property
    def instructions(self) -> int:
        return int(self.xnode.get("ic", "0"))

    @property
    def loops(self) -> int:
        return int(self.xnode.get("lc", "0"))

    @property
    def max_loopdepth(self) -> int:
        return int(self.xnode.get("ld", "0"))

    @property
    def has_error(self) -> bool:
        return self.xnode.get("tr", "ok") == "x"

    @property
    def name(self) -> Optional[str]:
        return self.xnode.get("name")

    def __str__(self) -> str:
        return (
            ("bc:" + str(self.basic_blocks)).ljust(10)
            + ("; ic: " + str(self.instructions)).ljust(14)
            + ("" if self.loops == 0 else ("; lc: " + str(self.loops))))


class AppCfgInfo:

    def __init__(self, xnode: Optional[ET.Element]) -> None:
        self.xnode = xnode
        self._function_cfg_infos: Optional[Dict[str, FnCfgInfo]] = None

    @property
    def function_cfg_infos(self) -> Dict[str, FnCfgInfo]:
        if self._function_cfg_infos is None:
            self._function_cfg_infos = {}
            self._initialize_functions()
        return self._function_cfg_infos

    @property
    def cfg_infos(self) -> List[FnCfgInfo]:
        return sorted(
            self.function_cfg_infos.values(),
            key = lambda c: c.faddr_i)

    def _initialize_functions(self) -> None:
        self._function_cfg_infos = {}
        if self.xnode is not None:
            for xf in self.xnode.findall("fn"):
                optva = xf.get("va")
                if optva is not None:
                    self._function_cfg_infos[optva] = FnCfgInfo(xf)
