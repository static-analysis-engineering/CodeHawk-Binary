# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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
"""Representation of MIPS registers."""

from typing import List, Optional, TYPE_CHECKING

from chb.app.BDictionaryRecord import bdregistry
from chb.app.Register import Register

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.app.BDictionary


class MIPSRegisterBase(Register):

    def __init__(
            self,
            bd: "chb.app.BDictionary.BDictionary",
            ixval: IndexedTableValue) -> None:
        Register.__init__(self, bd, ixval)

    def is_mips_register(self) -> bool:
        return False

    def is_mips_stack_pointer(self) -> bool:
        return False

    def is_mips_argument_register(self) -> bool:
        return False

    def is_mips_special_register(self) -> bool:
        return False

    def is_mips_floating_point_register(self) -> bool:
        return False


@bdregistry.register_tag("p", Register)
class MIPSRegister(MIPSRegisterBase):

    def __init__(self,
                 bd: "chb.app.BDictionary.BDictionary",
                 ixval: IndexedTableValue) -> None:
        MIPSRegisterBase.__init__(self, bd, ixval)

    @property
    def name(self) -> str:
        return self.tags[1]

    @property
    def is_mips_register(self) -> bool:
        return True

    @property
    def is_mips_argument_register(self) -> bool:
        return self.tags[1] in ['a0', 'a1', 'a2', 'a3']

    @property
    def is_mips_return_value_register(self) -> bool:
        return self.tags[1] in ["v0", "v1"]

    @property
    def is_mips_stack_pointer(self) -> bool:
        return self.tags[1] in ["sp"]

    @property
    def is_mips_callee_saved_register(self) -> bool:
        return self.tags[1] in ["s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"]

    @property
    def is_mips_global_pointer(self) -> bool:
        return self.tags[1] in ["gp"]

    @property
    def is_mips_return_address_register(self) -> bool:
        return self.tags[1] == "ra"

    def argument_index(self) -> int:
        if self.is_mips_argument_register:
            return int(self.tags[1][1:])
        else:
            raise UF.CHBError("MIPS register is not an argument register")

    def __str__(self) -> str:
        return self.name


@bdregistry.register_tag("ps", Register)
class MIPSSpecialRegister(MIPSRegisterBase):

    def __init__(self,
                 bd: "chb.app.BDictionary.BDictionary",
                 ixval: IndexedTableValue) -> None:
        MIPSRegisterBase.__init__(self, bd, ixval)

    def is_mips_special_register(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.tags[1]


@bdregistry.register_tag("pfp", Register)
class MIPSFloatingPointRegister(MIPSRegisterBase):

    def __init__(self,
                 bd: "chb.app.BDictionary.BDictionary",
                 ixval: IndexedTableValue) -> None:
        MIPSRegisterBase.__init__(self, bd, ixval)

    def is_mips_floating_point_register(self) -> bool:
        return True

    def get_register_index(self) -> int:
        return int(self.args[0])

    def __str__(self) -> str:
        return '$f' + str(self.get_register_index())
