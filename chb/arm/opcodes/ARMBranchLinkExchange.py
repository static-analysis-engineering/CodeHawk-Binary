# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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

from typing import (
    Any, cast, Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING)

from chb.app.InstrXData import InstrXData

from chb.arm.ARMCallOpcode import ARMCallOpcode
from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand
from chb.arm.ARMOperandKind import ARMOperandKind, ARMAbsoluteOp

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

from chb.bctypes.BCTyp import BCTyp

from chb.invariants.XXpr import XXpr
import chb.invariants.XXprUtil as XU

from chb.models.ModelsAccess import ModelsAccess
from chb.models.ModelsType import MNamedType

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.CallTarget import CallTarget, AppTarget
    from chb.arm.ARMDictionary import ARMDictionary


@armregistry.register_tag("BLX", ARMOpcode)
class ARMBranchLinkExchange(ARMCallOpcode):
    """Calls a subroutine at a PC-relative address.

    tags[1]: <c>
    args[0]: index of target operand in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMCallOpcode.__init__(self, d, ixval)
        self.check_key(2, 1, "BranchLinkExchange")

    def ast_prov(
            self,
            astree: ASTInterface,
            iaddr: str,
            bytestring: str,
            xdata: InstrXData) -> Tuple[
                List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return self.ast_call_prov(
            astree, iaddr, bytestring, "BranchLinkExchange (BLX)", xdata)
