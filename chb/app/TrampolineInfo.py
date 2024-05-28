# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2024  Aarno Labs, LLC
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
"""Representation of Environment and internal structure of trampoline."""

from typing import Dict, List, Optional, TYPE_CHECKING

import chb.util.fileutil as UF


if TYPE_CHECKING:
    from chb.cmdline.PatchResults import PatchEvent


class TrampolineInfo:

    def __init__(self, patchevent: "PatchEvent") -> None:
        self._patchevent = patchevent
        self._roles: Dict[str, str] = {}
        self._internal_edges: Dict[str, List[str]] = {}
        self._prenodes: List[str] = []
        self._postnodes: List[str] = []

    @property
    def patchevent(self) -> "PatchEvent":
        return self._patchevent

    @property
    def roles(self) -> Dict[str, str]:
        return self._roles

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def get_role_startaddr(self, role: str) -> Optional[str]:
        return self.roles.get(role, None)

    def add_role(self, name: str, addr: str) -> None:
        self._roles[name] = addr

    @property
    def firstaddr(self) -> str:
        setupb = self.get_role_startaddr("setupblock")
        if setupb is not None:
            return setupb
        else:
            raise UF.CHBError("Setup block not found in trampoline block")

    @property
    def internal_edges(self) -> Dict[str, List[str]]:
        return self._internal_edges

    def add_edge(self, src: str, tgt: str) -> None:
        self._internal_edges.setdefault(src, [])
        if not tgt in self.internal_edges[src]:
            self.internal_edges[src].append(tgt)

    @property
    def prenodes(self) -> List[str]:
        return self._prenodes

    def add_prenode(self, name: str) -> None:
        self._prenodes.append(name)

    @property
    def postnodes(self) -> List[str]:
        return self._postnodes

    def add_postnode(self, name: str) -> None:
        self._postnodes.append(name)

    @property
    def entrypoint(self) -> str:
        """Return the hex address in the original function from which the
        execution jumps to the trampoline.

        Note that this address is outside of the trampoline itself.
        In most cases this address is the same as (one of) the prenodes.
        """

        return self.patchevent.logicalva

    @property
    def wrapper_startaddr(self) -> str:
        return self.patchevent.wrapper.vahex

    @property
    def payload_startaddr(self) -> Optional[str]:
        if self.patchevent.has_payload():
            return self.patchevent.payload.vahex
        else:
            return None

    @property
    def payload_nodes(self) -> List[str]:
        result: List[str] = []
        for (role, addr) in self.roles.items():
            if role.startswith("payload"):
                result.append(addr)
        return result

    @property
    def cases(self) -> List[str]:
        return self.patchevent.cases

    @property
    def fallthrough_destination(self) -> Optional[str]:
        return self.patchevent.fallthrough_destination

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("entrypoint   : " + self.entrypoint)
        lines.append("wrapper start: " + self.wrapper_startaddr)
        if self.payload_startaddr is not None:
            lines.append("payload start: " + self.payload_startaddr)
        lines.append("cases        : [" + ", ".join(self.cases) + "]")
        lines.append("edges        :")
        for src in self.internal_edges:
            lines.append(
                "   ("
                + src + " ==> [" + ", ".join(self.internal_edges[src]) + "])")
        return "\n".join(lines)
