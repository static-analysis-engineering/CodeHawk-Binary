# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023-2024  Aarno Labs LLC
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
"""Stack local access within a function.

Corresponds to stack_access_t in bchlib/bCHLibTypes:

                                               tags[0]   tags    args
stack_access_t =
  | RegisterSpill                                "rs"      1      2
  | RegisterRestore                              "rr"      1      2
  | StackLoad                                    "sl"      1      4
  | StackStore                                   "ss"      1      5
  | StackBlockRead                               "br"      1      3
  | StackBlockWrite                              "bw"      1      3
"""

from typing import Optional, TYPE_CHECKING

from chb.app.Register import Register

from chb.invariants.FnDictionaryRecord import FnVarDictionaryRecord, varregistry

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.bctypes.BCTyp import BCTyp
    from chb.invariants.FnVarDictionary import FnVarDictionary
    from chb.invariants.VMemoryOffset import VMemoryOffset
    from chb.invariants.XVariable import XVariable
    from chb.invariants.XXpr import XXpr


class FnStackAccess(FnVarDictionaryRecord):

    def __init__(
            self, vd: "FnVarDictionary", ixval: IndexedTableValue) -> None:
        FnVarDictionaryRecord.__init__(self, vd, ixval)

    @property
    def size(self) -> Optional[int]:
        return None

    @property
    def is_register_spill(self) -> bool:
        return False

    @property
    def is_register_restore(self) -> bool:
        return False

    @property
    def is_load(self) -> bool:
        return False

    @property
    def is_store(self) -> bool:
        return False

    @property
    def is_block_read(self) -> bool:
        return False

    @property
    def is_block_write(self) -> bool:
        return False


@varregistry.register_tag("rs", FnStackAccess)
class FnStackRegisterSpill(FnStackAccess):
    """Initial value of register gets stored on the stack.

    args[0]: offset
    args[1]: index of register in bdictionary
    """

    def __init__(
            self, vd: "FnVarDictionary", ixval: IndexedTableValue) -> None:
        FnStackAccess.__init__(self, vd, ixval)

    @property
    def offset(self) -> int:
        return self.args[0]

    @property
    def register(self) -> Register:
        return self.bd.register(self.args[1])

    @property
    def size(self) -> Optional[int]:
        return 4

    @property
    def is_register_spill(self) -> bool:
        return True

    def __str__(self) -> str:
        return "spill(" + str(self.offset) + ", " + str(self.register) + ")"


@varregistry.register_tag("rr", FnStackAccess)
class FnStackRegisterRestore(FnStackAccess):
    """Initial value of register gets rerstored from the stack.

    args[0]: offset
    args[1]: index of register in bdictionary
    """

    def __init__(
            self, vd: "FnVarDictionary", ixval: IndexedTableValue) -> None:
        FnStackAccess.__init__(self, vd, ixval)

    @property
    def offset(self) -> int:
        return self.args[0]

    @property
    def register(self) -> Register:
        return self.bd.register(self.args[1])

    @property
    def size(self) -> Optional[int]:
        return 4

    @property
    def is_register_restore(self) -> bool:
        return True

    def __str__(self) -> str:
        return "restore(" + str(self.offset) + ", " + str(self.register) + ")"


@varregistry.register_tag("sl", FnStackAccess)
class FnStackLoad(FnStackAccess):
    """Value gets loaded from the stack.

    args[0]: index of stack variable in vardictionary
    args[1]: offset
    args[2]: size in bytes or -1 if not available
    args[3]: index of stack variable type in bcdictionary
    """

    def __init__(
            self, vd: "FnVarDictionary", ixval: IndexedTableValue) -> None:
        FnStackAccess.__init__(self, vd, ixval)

    @property
    def stackvar(self) -> "XVariable":
        return self.xd.variable(self.args[0])

    @property
    def offset(self) -> "VMemoryOffset":
        """Returns offset relative to the stack slot it is part of."""

        return self.vd.memory_offset(self.args[1])

    @property
    def size(self) -> Optional[int]:
        if self.args[2] == -1:
            return None
        else:
            return self.args[2]

    @property
    def stackvar_type(self) -> "BCTyp":
        return self.bcd.typ(self.args[3])

    @property
    def is_load(self) -> bool:
        return True

    def __str__(self) -> str:
        return (
            "stack-load("
            + str(self.stackvar)
            + ", "
            + str(self.offset)
            + ", "
            + str(self.size)
            + ", "
            + str(self.stackvar_type)
            + ")")


@varregistry.register_tag("ss", FnStackAccess)
class FnStackStore(FnStackAccess):
    """Value gets stored to the stack.

    args[0]: index of stack variable in vardictionary
    args[1]: offset
    args[2]: size in bytes or -1 if not available
    args[3]: index of stack variable type in bcdictionary
    args[4]: index of value stored in xprdictionary or -1 if n/a
    """

    def __init__(
            self, vd: "FnVarDictionary", ixval: IndexedTableValue) -> None:
        FnStackAccess.__init__(self, vd, ixval)

    @property
    def stackvar(self) -> "XVariable":
        return self.xd.variable(self.args[0])

    @property
    def offset(self) -> "VMemoryOffset":
        """Returns offset relative to the stack slot it is part of."""

        return self.vd.memory_offset(self.args[1])

    @property
    def size(self) -> Optional[int]:
        if self.args[2] == -1:
            return None
        else:
            return self.args[2]

    @property
    def stackvar_type(self) -> "BCTyp":
        return self.bcd.typ(self.args[3])

    @property
    def value(self) -> "XXpr":
        return self.xd.xpr(self.args[4])

    @property
    def is_store(self) -> bool:
        return True

    def __str__(self) -> str:
        return (
            "stack-store("
            + str(self.stackvar)
            + ", "
            + str(self.offset)
            + ", "
            + str(self.size)
            + ", "
            + str(self.stackvar_type)
            + ", "
            + str(self.value)
            + ")")


@varregistry.register_tag("br", FnStackAccess)
class FnStackBlockRead(FnStackAccess):
    """Value gets loaded from the stack.

    args[0]: offset
    args[1]: size in bytes or -1 if not available
    args[2]: index of stack variable type in bcdictionary
    """

    def __init__(
            self, vd: "FnVarDictionary", ixval: IndexedTableValue) -> None:
        FnStackAccess.__init__(self, vd, ixval)

    @property
    def offset(self) -> int:
        return self.args[0]

    @property
    def size(self) -> Optional[int]:
        if self.args[1] == -1:
            return None
        else:
            return self.args[1]

    @property
    def stackvar_type(self) -> "BCTyp":
        return self.bcd.typ(self.args[2])

    @property
    def is_block_read(self) -> bool:
        return True

    def __str__(self) -> str:
        return (
            "stack-block-read("
            + str(self.offset)
            + ", "
            + str(self.size)
            + ", "
            + str(self.stackvar_type)
            + ")")
    
    

@varregistry.register_tag("bw", FnStackAccess)
class FnStackBlockWrite(FnStackAccess):
    """Sequence of bytes gets written to the stack

    args[0]: offset
    args[1]: size in bytes or -1 if not available
    args[2]: index of stack variable type in bcdictionary
    args[3]: index of value stored in xprdictionary or -1 if n/a
    """

    def __init__(
            self, vd: "FnVarDictionary", ixval: IndexedTableValue) -> None:
        FnStackAccess.__init__(self, vd, ixval)

    @property
    def offset(self) -> int:
        return self.args[0]

    @property
    def size(self) -> Optional[int]:
        if self.args[1] == -1:
            return None
        else:
            return self.args[1]

    @property
    def stackvar_type(self) -> "BCTyp":
        return self.bcd.typ(self.args[2])

    @property
    def value(self) -> "XXpr":
        return self.xd.xpr(self.args[3])

    @property
    def is_block_write(self) -> bool:
        return True

    def __str__(self) -> str:
        return (
            "stack-block-write("
            + str(self.offset)
            + ", "
            + str(self.size)
            + ", "
            + str(self.stackvar_type)
            + ", "
            + str(self.value)
            + ")")
