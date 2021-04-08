# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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
"""Abstract superclass for different types of assembly functions.

Subclasses:
 - AsmFunction
 - MIPSFunction
 - ARMFunction
"""

import hashlib
import xml.etree.ElementTree as ET

from typing import Callable, Dict, List, Mapping, Optional, TYPE_CHECKING

import chb.app.BasicBlock as B
import chb.app.Cfg as C
import chb.app.FunctionDictionary as F
import chb.app.Instruction as I
import chb.invariants.FnInvDictionary as INV
import chb.invariants.FnXprDictionary as X
import chb.invariants.FnVarDictionary as V
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.app.AppAccess


class Function:

    def __init__(
            self,
            app: "chb.app.AppAccess.AppAccess",
            xnode: ET.Element) -> None:
        self._app = app
        self.xnode = xnode
        self._vd: Optional[V.FnVarDictionary] = None
        self._id: Optional[INV.FnInvDictionary] = None
        self._fnd: Optional[F.FunctionDictionary] = None

    @property
    def faddr(self) -> str:
        faddr = self.xnode.get("a")
        if faddr is None:
            raise UF.CHBError("Assembly function address is missing from xml")
        return faddr

    @property
    def app(self) -> "chb.app.AppAccess.AppAccess":
        return self._app

    @property
    def fndictionary(self) -> F.FunctionDictionary:
        if self._fnd is None:
            xfnd = self.xnode.find("instr-dictionary")
            if xfnd is None:
                raise UF.CHBError("Element instr-dictionary missing from xml")
            self._fnd = F.FunctionDictionary(self, xfnd)
        return self._fnd

    @property
    def vardictionary(self) -> V.FnVarDictionary:
        if self._vd is None:
            xvd = UF.get_function_vars_xnode(
                self.app.path, self.app.filename, self.faddr)
            xvard = xvd.find("var-dictionary")
            if xvard is None:
                raise UF.CHBError("Var-dictionary element not found")
            self._vd = V.FnVarDictionary(self, xvard)
        return self._vd

    @property
    def xprdictionary(self) -> X.FnXprDictionary:
        return self.vardictionary.xd

    @property
    def invdictionary(self) -> INV.FnInvDictionary:
        if self._id is None:
            xinvnode = UF.get_function_invs_xnode(
                self.app.path, self.app.filename, self.faddr)
            xinvd = xinvnode.get("inv-dictionary")
            if xinvd is None:
                raise UF.CHBError("Inv-dictionary element not found")
            self._id = INV.FnInvDictionary(self.vardictionary, xinvd)
        return self._id

    @property
    def has_name(self) -> bool:
        return self.app.functionsdata.has_name(self.faddr)

    @property
    def names(self) -> List[str]:
        if self.has_name:
            return self.app.functionsdata.get_names(self.faddr)
        return []

    @property
    def blocks(self) -> Mapping[str, B.BasicBlock]:
        raise UF.CHBError("Property blocks not implemented for Function")

    @property
    def instructions(self) -> Mapping[str, I.Instruction]:
        result: Dict[str, I.Instruction] = {}
        for b in self.blocks:
            result.update(self.blocks[b].instructions)
        return result

    @property
    def cfg(self) -> C.Cfg:
        raise UF.CHBError("Property cfg not implemented for Function")

    @property
    def strings(self) -> List[str]:
        result: List[str] = []

        def f(iaddr: str, instr: I.Instruction) -> None:
            result.extend(instr.strings)

        self.iter_instructions(f)
        return result

    @property
    def md5(self) -> str:
        m = hashlib.md5()

        def f(iaddr: str, instr: I.Instruction) -> None:
            m.update(instr.bytestring.encode("utf-8"))

        self.iter_instructions(f)
        return m.hexdigest()

    def get_block(self, baddr: str) -> B.BasicBlock:
        if baddr in self.blocks:
            return self.blocks[baddr]
        else:
            raise UF.CHBError("Block with address " + baddr + " not found")

    def has_instruction(self, iaddr: str) -> bool:
        for b in self.blocks:
            if self.blocks[b].has_instruction(iaddr):
                return True
        return False

    def get_instruction(self, iaddr: str) -> I.Instruction:
        for b in self.blocks:
            if self.blocks[b].has_instruction(iaddr):
                return self.blocks[b].get_instruction(iaddr)
        else:
            raise UF.CHBError("No instruction found at address " + iaddr)

    def iter_blocks(self, f: Callable[[str, B.BasicBlock], None]) -> None:
        for baddr in sorted(self.blocks):
            f(baddr, self.blocks[baddr])

    def iter_instructions(self, f: Callable[[str, I.Instruction], None]) -> None:
        for iaddr in sorted(self.instructions):
            f(iaddr, self.instructions[iaddr])

    def get_names(self) -> List[str]:
        if self.has_name:
            return self.app.functionsdata.get_names(self.faddr)
        else:
            return []
