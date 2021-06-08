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
"""X86 CPU Register data."""

from typing import List, TYPE_CHECKING

from chb.app.BDictionaryRecord import bdregistry
from chb.app.Register import Register

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.app.BDictionary


class X86Register(Register):
    """Superclass of the different types of x86 registers.

    Part of bchlib:register_t sumtype
    """

    def __init__(
            self,
            bd: "chb.app.BDictionary.BDictionary",
            ixval: IndexedTableValue) -> None:
        Register.__init__(self, bd, ixval)

    def is_cpu_register(self) -> bool:
        return False

    def is_segment_register(self) -> bool:
        return False

    def is_double_register(self) -> bool:
        return False

    def is_floating_point_register(self) -> bool:
        return False

    def is_control_register(self) -> bool:
        return False

    def is_debug_register(self) -> bool:
        return False

    def is_mmx_register(self) -> bool:
        return False

    def is_xmm_register(self) -> bool:
        return False


@bdregistry.register_tag("c", Register)
class CPURegister(X86Register):
    """Regular x86 register.

    tags[1]: name
    """

    def __init__(
            self,
            bd: "chb.app.BDictionary.BDictionary",
            ixval: IndexedTableValue) -> None:
        X86Register.__init__(self, bd, ixval)

    def is_cpu_register(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.tags[1]


@bdregistry.register_tag("s", Register)
class SegmentRegister(X86Register):
    """X86 segment register.

    tags[1]: name
    """

    def __init__(
            self,
            bd: "chb.app.BDictionary.BDictionary",
            ixval: IndexedTableValue) -> None:
        X86Register.__init__(self, bd, ixval)

    def is_segment_register(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.tags[1]


@bdregistry.register_tag("d", Register)
class DoubleRegister(X86Register):
    """Register that spans two regular registers.

    tags[1]: name-1
    tags[2]: name-2
    """

    def __init__(
            self,
            bd: "chb.app.BDictionary.BDictionary",
            ixval: IndexedTableValue) -> None:
        X86Register.__init__(self, bd, ixval)

    def is_double_register(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.tags[1] + ':' + self.tags[2]


@bdregistry.register_tag("f", Register)
class FloatingPointRegister(X86Register):
    """X86 floating point register.

    args[0]: index number
    """

    def __init__(
            self,
            bd: "chb.app.BDictionary.BDictionary",
            ixval: IndexedTableValue) -> None:
        X86Register.__init__(self, bd, ixval)

    def is_floating_point_register(self) -> bool:
        return True

    def get_index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return 'st(' + str(self.get_index()) + ')'


@bdregistry.register_tag("ctr", Register)
class ControlRegister(X86Register):
    """X86 Control register.

    args[0]: index number
    """

    def __init__(
            self,
            bd: "chb.app.BDictionary.BDictionary",
            ixval: IndexedTableValue) -> None:
        X86Register.__init__(self, bd, ixval)

    def is_control_register(self) -> bool:
        return True

    def get_index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return "CR" + str(self.get_index())


@bdregistry.register_tag("dbg", Register)
class DebugRegister(X86Register):
    """X86 DR register.

    args[0]: index number
    """

    def __init__(self,
                 bd: "chb.app.BDictionary.BDictionary",
                 ixval: IndexedTableValue) -> None:
        X86Register.__init__(self, bd, ixval)

    def is_debug_register(self) -> bool:
        return True

    def get_index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return 'DR' + str(self.get_index())


@bdregistry.register_tag("m", Register)
class MmxRegister(X86Register):
    """MMX Register.

    args[0]: index number
    """

    def __init__(self,
                 bd: "chb.app.BDictionary.BDictionary",
                 ixval: IndexedTableValue) -> None:
        X86Register.__init__(self, bd, ixval)

    def is_mmx_register(self) -> bool:
        return True

    def get_index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return 'mm(' + str(self.get_index()) + ')'


@bdregistry.register_tag("x", Register)
class XmmRegister(X86Register):
    """Xmm register.

    args[0]: index number
    """

    def __init__(self,
                 bd: "chb.app.BDictionary.BDictionary",
                 ixval: IndexedTableValue) -> None:
        X86Register.__init__(self, bd, ixval)

    def is_xmm_register(self) -> bool:
        return True

    def get_index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return 'xmm(' + str(self.get_index()) + ')'
