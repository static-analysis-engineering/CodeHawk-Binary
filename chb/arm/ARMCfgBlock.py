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
"""Control flow graph basic block of ARM function."""

import xml.etree.ElementTree as ET

from chb.app.CfgBlock import CfgBlock

import chb.util.fileutil as UF

from typing import Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from chb.arm.ARMCfg import ARMCfg


class ARMCfgBlock(CfgBlock):

    def __init__(self, cfg: "ARMCfg", xnode: ET.Element) -> None:
        CfgBlock.__init__(self, xnode)
        self._armcfg = cfg



class ARMCfgTrampolineBlock(ARMCfgBlock):

    def __init__(
            self,
            cfg: "ARMCfg",
            xnode: ET.Element) -> None:
        pass
