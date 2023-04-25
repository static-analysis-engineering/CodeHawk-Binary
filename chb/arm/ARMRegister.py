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
"""Representation of ARM registers.

Subclass of chb.app.Register

ARM specific register types:

    Corresponding type in bCHLibTypes:
                                                   tags[0]     tags   args
    ----------------------------------------------------------------------------
    type register_t =
    | ARMRegister of arm_reg_t                       "a"         2      0
    | ARMDoubleRegister of arm_reg_t * arm_reg_t     "armd"      3      0
    | ARMSpecialRegister of arm_special_reg_t        "as"        2      0
    | ARMExtensionR of                               "armx"      1      1
        arm_extension_register_t 
    | ARMDoubleExtensionReg of                       "armdx"     1      2
        arm_extension_register_t
        * arm_extension_register_t
    | ARMExtensionRegElement of                      "armxe"     1      1
        arm_extension_register_element_t
    | ARMExtensionRegReplicatedElement of            "armxr"     1      1
        arm_extension_register_replicated_element_t
"""

from typing import TYPE_CHECKING

from chb.app.BDictionaryRecord import bdregistry
from chb.app.Register import Register

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary
    from chb.app.ARMExtensionRegister import ARMExtensionRegister


@bdregistry.register_tag("a", Register)
class ARMRegister(Register):

    def __init__(self, bd: "BDictionary", ixval: IndexedTableValue) -> None:
        Register.__init__(self, bd, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def is_arm_register(self) -> bool:
        return True

    @property
    def is_arm_stack_pointer(self) -> bool:
        return self.register == "SP"

    @property
    def is_arm_argument_register(self) -> bool:
        return self.register in ["R0", "R1", "R2", "R3"]

    @property
    def is_arm_callee_saved_register(self) -> bool:
        return self.tags[1] in [
            "R4", "R5", "R6", "R7", "R8", "R9", "R10", "R11", "LR"]

    def argument_index(self) -> int:
        if self.is_arm_argument_register:
            return int(self.register[1:])
        else:
            raise UF.CHBError(
                "Register is not an argument register: " + str(self))

    def __str__(self) -> str:
        return self.tags[1]


@bdregistry.register_tag("armd", Register)
class ARMDoubleRegister(Register):

    def __init__(self, bd: "BDictionary", ixval: IndexedTableValue) -> None:
        Register.__init__(self, bd, ixval)

    @property
    def register1(self) -> str:
        return self.tags[1]

    @property
    def register2(self) -> str:
        return self.tags[2]

    def __str__(self) -> str:
        return self.register1 + "_" + self.register2


@bdregistry.register_tag("armx", Register)
class ARMExtensionReg(Register):

    def __init__(self, bd: "BDictionary", ixval: IndexedTableValue) -> None:
        Register.__init__(self, bd, ixval)

    @property
    def xregister(self) -> "ARMExtensionRegister":
        return self.bd.arm_extension_register(self.args[0])

    def __str__(self) -> str:
        return str(self.xregister)
