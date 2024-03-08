# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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
    from chb.app.TrampolineInfo import TrampolineInfo
    from chb.arm.ARMCfg import ARMCfg
    from chb.invariants.XXpr import XXpr


class ARMCfgBlock(CfgBlock):

    def __init__(self, xnode: ET.Element) -> None:
        CfgBlock.__init__(self, xnode)



class ARMCfgTrampolineBlock(ARMCfgBlock):
    """A trampoline block represents a connected set of nodes.

    Because this node represents multiple nodes, the xnode given
    is the xnode of the Cfg rather than that of the node, which
    it normally is, so all methods that rely on xnode must be
    overridden.

    The usual assumptions about a basic block, that is, that it
    is straight-through code with a single entry point and a
    single exit point, and execution is all or nothing, do not
    hold for a trampoline block. It can (and usually does) have
    multiple connected basic block, each of which has their own
    role in the trampoline.

    The internal structure is represented by the trampoline_info,
    which contains the roles, the internal edges, and the addresses
    of nodes that jump to the trampoline and those to which the
    trampoline jumps back.

    A minimum trampoline could be a single block that performs a
    single straight-line sequence of instructions and jumps back
    to the original location.

    More commonly there is a setup block that saves the context
    (registers) to the stack, followed by a call to a 'payload'
    function that performs a check or some other conditional action
    (this function is inlined) and a takedown block that restores
    the context before jumping back to the originating function.

    In principle the payload can have arbitrarily complex internal
    structure (including loops), although that is currently not very
    well supported in the liftings.
    """

    def __init__(
            self,
            xnode: ET.Element,
            trinfo: "TrampolineInfo") -> None:
        ARMCfgBlock.__init__(self, xnode)
        self._trinfo = trinfo
        self._xblocks: Dict[str, ET.Element] = {}

    @property
    def xblocks(self) -> Dict[str, ET.Element]:
        if len(self._xblocks) == 0:
            cfgblocks = self.xnode.find("blocks")
            if cfgblocks is None:
                raise UF.CHBError(
                    "Blocks are missing from arm cfg in trampoline block")
            for b in cfgblocks.findall("bl"):
                xbaddr = b.get("ba")
                if xbaddr is not None:
                    self._xblocks[xbaddr] = b
        return self._xblocks

    def block_xnode(self, addr: str) -> ET.Element:
        return self.xblocks[addr]

    @property
    def loop_levels(self) -> List[str]:
        raise UF.CHBError(
            "Loop-levels: not well-defined for a trampoline block")

    @property
    def in_loops(self) -> bool:
        return False

    @property
    def firstaddr(self) -> str:
        return self.trampoline_info.firstaddr

    @property
    def lastaddr(self) -> str:
        raise UF.CHBError(
            "Last address of trampoline block is not well defined")

    @property
    def is_trampoline(self) -> bool:
        return True

    @property
    def trampoline_info(self) -> "TrampolineInfo":
        return self._trinfo

    @property
    def roles(self) -> Dict[str, str]:
        """Returns a mapping between role name and block hex address."""

        return self.trampoline_info.roles

    @property
    def prenodes(self) -> List[str]:
        """Returns nodes with an edge into the trampoline."""

        return self.trampoline_info.prenodes

    @property
    def postnodes(self) -> List[str]:
        """Returns nodes that are the target of an edge out of the trampoline."""

        return self.trampoline_info.postnodes

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("Trampoline block")
        lines.append(str(self.trampoline_info))
        return "\n".join(lines)
