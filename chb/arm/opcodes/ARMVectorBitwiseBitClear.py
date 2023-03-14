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

from typing import List, TYPE_CHECKING

from chb.app.InstrXData import InstrXData

from chb.arm.ARMDictionaryRecord import armregistry
from chb.arm.ARMOpcode import ARMOpcode, simplify_result
from chb.arm.ARMOperand import ARMOperand

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMVfpDatatype import ARMVfpDatatype


@armregistry.register_tag("VBIC", ARMOpcode)
class ARMVectorBitwiseBitClear(ARMOpcode):
    """Performs a bitwise AND between a register and an immediate.

    VBIC<c> <Qd>, <Qn>, <Qm>
    VBIC<c> <Dd>, <Dn>, <Dm>

    VBIC<c>.<dt> <Qd>, #<imm>
    VBIC<c>.<dt> <Dd>, #<imm>

    tags[1]: <c>
    args[0]: index of datatype in armdictionary
    args[1]: index of qd in arm dictionary
    args[2]: index of qn in arm dictionary
    args[3]: index of qm/imm in arm dictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOpcode.__init__(self, d, ixval)
        self.check_key(2, 4, "VectorBitwiseBitClear")

    @property
    def operands(self) -> List[ARMOperand]:
        if self.vfp_datatype.is_vfpnone:
            return [self.armd.arm_operand(self.args[i]) for i in [1, 2, 3]]
        else:
            return [self.armd.arm_operand(self.args[i]) for i in [1, 3]]

    def mnemonic_extension(self) -> str:
        if self.vfp_datatype.is_vfpnone:
            return ARMOpcode.mnemonic_extension(self)
        else:
            cc = ARMOpcode.mnemonic_extension(self)
            vfpdt = str(self.vfp_datatype)
            return cc + vfpdt

    @property
    def vfp_datatype(self) -> "ARMVfpDatatype":
        return self.armd.arm_vfp_datatype(self.args[0])

    def annotation(self, xdata: InstrXData) -> str:
        return "pending"
