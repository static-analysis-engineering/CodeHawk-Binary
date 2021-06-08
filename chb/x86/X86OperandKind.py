# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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
"""Different kinds of operands of x86 assembly instructions."""

from typing import List, Optional, TYPE_CHECKING

from chb.app.BDictionary import BDictionary, AsmAddress
from chb.x86.X86DictionaryRecord import X86DictionaryRecord, x86registry

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary


class X86OperandKind(X86DictionaryRecord):
    """Identifies the kind of operand of an x86 assembly instruction.

    Corresponds to bCHLibx86Types:
                                              tags[0]    tags    args
    ----------------------------------------------------------------------------
    type asm_operand_kind_t =
    | Flag of eflag_t                           "v"        2       0
    | Reg of cpureg_t                           "r"        2       0
    | FpuReg of int                             "f"        1       1
    | ControlReg of int                         "c"        1       1
    | DebugReg of int                           "d"        1       1
    | MmReg of int                              "m"        1       1
    | XmmReg of int                             "x"        1       1
    | SegReg of segment_t                       "s"        2       0
    | IndReg of cpureg_t * numerical_t          "ri"       3       0
    | SegIndReg of                              "si"       4       0
         segment_t
         * cpureg_t * numerical_t
    | ScaledIndReg of                           "rs"       4       1
         cpureg_t option
         * cpureg_t option
         * int
         * numerical_t
    | DoubleReg of cpureg_t * cpureg_t           "rd"      3       0
    | Imm of immediate_int                       "i"       2       0
    | Absolute of doubleword_int                 "a"       1       1
    | SegAbsolute of                             "sa"      2       1
         segment_t
         * doubleword_int
    | DummyOp                                    "u"       1       0

    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86DictionaryRecord.__init__(self, d, ixval)

    @property
    def is_flag(self) -> bool:
        return False

    @property
    def is_register(self) -> bool:
        return False

    @property
    def is_immediate(self) -> bool:
        return False

    @property
    def is_absolute(self) -> bool:
        return False

    @property
    def is_indirect_register(self) -> bool:
        return False

    @property
    def is_scaled_indirect_register(self) -> bool:
        return False

    @property
    def is_double_register(self) -> bool:
        return False

    def to_operand_string(self) -> str:
        return self.__str__()

    def to_address_string(self) -> str:
        return 'address-string?'

    def __str__(self) -> str:
        return 'operandkind:' + self.tags[0]


@x86registry.register_tag("v", X86OperandKind)
class X86FlagOp(X86OperandKind):
    """Processor flag.

    tags[1]: name
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def is_flag(self) -> bool:
        return True

    @property
    def flag(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return str(self.flag)


@x86registry.register_tag("r", X86OperandKind)
class X86RegisterOp(X86OperandKind):
    """General x86 register.

    tags[1]: name
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def is_register(self) -> bool:
        return True

    @property
    def register(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return str(self.register)


@x86registry.register_tag("f", X86OperandKind)
class X86FpuRegisterOp(X86OperandKind):
    """ Floating point register

    args[0]: index number
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def register_index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return '%st(' + str(self.register_index) + ')'


@x86registry.register_tag("c", X86OperandKind)
class X86ControlRegisterOp(X86OperandKind):
    """Control register

    args[0]: index number
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def register_index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return 'CR' + str(self.register_index)


@x86registry.register_tag("d", X86OperandKind)
class X86DebugRegisterOp(X86OperandKind):
    """Debug register

    args[0]: index number
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def register_index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return 'DR' + str(self.register_index)


@x86registry.register_tag("m", X86OperandKind)
class X86MmRegisterOp(X86OperandKind):
    """Mm register

    args[0]: index number
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def register_index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return '%mm' + str(self.register_index)


@x86registry.register_tag("x", X86OperandKind)
class X86XmmRegisterOp(X86OperandKind):
    """Xmm register

    args[0]: index number
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def register_index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return '%xmm' + str(self.register_index)


@x86registry.register_tag("s", X86OperandKind)
class X86SegRegisterOp(X86OperandKind):
    """Segment register

    tags[1]: name
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return str(self.register)


@x86registry.register_tag("ri", X86OperandKind)
class X86IndirectRegisterOp(X86OperandKind):
    """Indirect register

    tags[1]: register name
    tags[2]: offset (string)
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def is_indirect_register(self) -> bool:
        return True

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def offset(self) -> int:
        return int(self.tags[2])

    def to_operand_string(self) -> str:
        offset = self.offset
        if offset == 0:
            index = str(self.register)
        elif offset > 0:
            index = str(self.register + '+' + str(offset))
        else:
            index = str(self.register + '-' + str(abs(offset)))
        return 'mem[' + index + ']'

    def to_address_string(self) -> str:
        offset = self.offset
        if offset == 0:
            return str(self.register)
        elif offset > 0:
            return str(self.register) + '+' + str(offset)
        else:
            return str(self.register) + '-' + str(abs(offset))

    def __str__(self) -> str:
        return str(self.offset) + '(' + str(self.register) + ')'


@x86registry.register_tag("si", X86OperandKind)
class X86SegIndirectRegisterOp(X86OperandKind):
    """Indirect segment register.

    tags[1]: segment register name
    tags[2]: cpu register name
    tags[3]: offset (string)
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)


@x86registry.register_tag("u", X86OperandKind)
class DummyOp(X86OperandKind):
    """No knowledge about operand."""

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)


@x86registry.register_tag("rs", X86OperandKind)
class X86ScaledIndirectRegisterOp(X86OperandKind):
    """Scaled indirect register.

    tags[1]: base register name ("none" if not present)
    tags[2]: index register name ("none" if not present)
    tags[3]: offset (string)
    args[0]: scale
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def is_scaled_indirect_register(self) -> bool:
        return True

    @property
    def base_register(self) -> Optional[str]:
        return None if self.tags[1] == "none" else self.tags[1]

    @property
    def index_register(self) -> Optional[str]:
        return None if self.tags[2] == "none" else self.tags[2]

    @property
    def scale(self) -> int:
        return self.args[0]

    @property
    def offset(self) -> int:
        return int(self.tags[3])

    def __str__(self) -> str:
        r1 = self.base_register
        if r1 is None:
            r1 = ""
        r2 = self.index_register
        if r2 is None:
            r2 = ""
        return (str(self.offset)
                + '('
                + r1
                + ','
                + r2
                + ','
                + str(self.scale)
                + ')')


@x86registry.register_tag("rd", X86OperandKind)
class X86DoubleRegisterOp(X86OperandKind):
    """Double register

    tags[1]: name of high register
    tags[2]: name of low register
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def is_double_register(self) -> bool:
        return True

    @property
    def register_high(self) -> str:
        return self.tags[1]

    @property
    def register_low(self) -> str:
        return self.tags[2]

    def __str__(self) -> str:
        return self.register_high + ':' + self.register_low


@x86registry.register_tag("i", X86OperandKind)
class X86ImmediateOp(X86OperandKind):
    """Immediate value.

    tags[1]: value (string)
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def is_immediate(self) -> bool:
        return True

    @property
    def value(self) -> int:
        return int(self.tags[1])

    def __str__(self) -> str:
        return str(hex(self.value))


@x86registry.register_tag("a", X86OperandKind)
class X86AbsoluteOp(X86OperandKind):
    """Absolute address (pointer).

    args[0]: index of address in bdictionary
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def address(self) -> AsmAddress:
        return self.bd.address(self.args[0])

    @property
    def is_absolute(self) -> bool:
        return True

    def __str__(self) -> str:
        return str(self.address)


@x86registry.register_tag("sa", X86OperandKind)
class SegAbsoluteOp(X86OperandKind):
    """Segment register absolute address.

    tags[1]: name of segment register
    args[0]: index of address in bdictionary
    """

    def __init__(
            self,
            d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86OperandKind.__init__(self, d, ixval)

    @property
    def segment(self) -> str:
        return self.tags[0]

    @property
    def address(self) -> AsmAddress:
        return self.bd.address(self.args[0])

    def __str__(self) -> str:
        return self.segment + ':' + str(self.address)
