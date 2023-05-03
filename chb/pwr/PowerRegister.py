# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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
"""Representation of Power registers (in bdictionary).

Subclass of chb.app.Register

Power specific register types:

Corresponding type in bCHLibTypes:
                                                tag[0]    tags    args
--------------------------------------------------------------------------------
| PowerGPRegister of int                       "pwrgpr"    1       1
| PowerSPRegister of pwr_special_reg_t         "pwrspr"    2       0
| PowerCRField of pwr_register_field_t         "pwrcrf"    2       0
"""

from typing import TYPE_CHECKING

from chb.app.BDictionaryRecord import bdregistry
from chb.app.Register import Register

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary


@bdregistry.register_tag("pwrgpr", Register)
class PowerGPRegister(Register):

    def __init__(self, bd: "BDictionary", ixval: IndexedTableValue) -> None:
        Register.__init__(self, bd, ixval)

    @property
    def register(self) -> str:
        return "r" + str(self.args[0])

    @property
    def rindex(self) -> int:
        return self.args[0]

    @property
    def is_pwr_gp_register(self) -> bool:
        return True

    @property
    def is_power_register(self) -> bool:
        return True

    @property
    def is_power_stack_pointer(self) -> bool:
        return self.rindex == 1

    @property
    def is_power_argument_register(self) -> bool:
        return self.rindex >= 3 and self.rindex <= 10

    def argument_index(self) -> int:
        if self.is_power_argument_register:
            return self.rindex - 3
        else:
            raise UF.CHBError(
                "Register is not an argument register: " + str(self))

    def __str__(self) -> str:
        return self.register


@bdregistry.register_tag("pwrspr", Register)
class PowerSPRegister(Register):

    def __init__(self, bd: "BDictionary", ixval: IndexedTableValue) -> None:
        Register.__init__(self, bd, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def is_pwr_sp_register(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.register
