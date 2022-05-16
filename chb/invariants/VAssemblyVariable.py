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
"""Different types of variables.

Corresponds to assembly_variable_denotation_t in bchlib/bCHLibTypes:

                                                      tags[0]   tags    args
type assembly_variable_denotation_t =
  | MemoryVariable of int * memory_offset_t             "m"       1       2
  | RegisterVariable of register_t                      "r"       1       1
  | CPUFlagVariable of eflag_t                          "f"       2       0
  | AuxiliaryVariable of constant_value_variable_t      "a"       1       1

"""

from typing import List, Sequence, Tuple, TYPE_CHECKING

from chb.app.Register import Register

from chb.invariants.FnDictionaryRecord import FnVarDictionaryRecord, varregistry
from chb.invariants.VConstantValueVariable import VConstantValueVariable
from chb.invariants.VMemoryBase import VMemoryBase
from chb.invariants.VMemoryOffset import VMemoryOffset

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.invariants.FnVarDictionary import FnVarDictionary
    from chb.invariants.XXpr import XXpr
    from chb.invariants.XVariable import XVariable


class VAssemblyVariable(FnVarDictionaryRecord):

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        FnVarDictionaryRecord.__init__(self, vd, ixval)

    @property
    def is_memory_variable(self) -> bool:
        return False

    @property
    def is_basevar_variable(self) -> bool:
        return False

    @property
    def is_register_variable(self) -> bool:
        return False

    @property
    def is_cpu_flag_variable(self) -> bool:
        return False

    @property
    def is_auxiliary_variable(self) -> bool:
        return False

    @property
    def is_global_variable(self) -> bool:
        return False

    @property
    def is_global_value(self) -> bool:
        return False

    @property
    def has_global_base(self) -> bool:
        return False

    @property
    def is_stack_base_address(self) -> bool:
        return False

    @property
    def is_heap_base_address(self) -> bool:
        return False

    @property
    def is_stack_argument(self) -> bool:
        return False

    @property
    def is_argument_value(self) -> bool:
        return False

    @property
    def is_argument_deref_value(self) -> bool:
        return False

    @property
    def is_function_return_value(self) -> bool:
        return False

    @property
    def is_initial_memory_value(self) -> bool:
        return False

    @property
    def is_bridge_variable(self) -> bool:
        return False

    @property
    def is_structured_var(self) -> bool:
        """Returns true if this variable is a memory dereference."""
        return (self.is_basevar_variable
                or (self.is_auxiliary_variable
                    and self.auxvar.is_structured_value))

    @property
    def auxvar(self) -> VConstantValueVariable:
        raise UF.CHBError("Auxvar property not supported for " + str(self))

    @property
    def offset(self) -> VMemoryOffset:
        raise UF.CHBError("Offset property not supported for " + str(self))

    @property
    def basevar(self) -> "XVariable":
        raise UF.CHBError("Basevar not supported for " + str(self))

    def global_base(self) -> "VAssemblyVariable":
        raise UF.CHBError("Global_base not supported for " + str(self))

    def argument_index(self) -> int:
        raise UF.CHBError("Argument_index not supported for " + str(self))

    def argument_deref_arg_offset(
            self, inbytes: bool = False) -> Tuple[int, int]:
        raise UF.CHBError("Get_argument_deref_arg_offset not supported for "
                          + str(self))

    def call_arguments(self) -> Sequence["XXpr"]:
        raise UF.CHBError("Get_call_arguments not supported for " + str(self))

    def __str__(self) -> str:
        return "assembly-variable:" + self.tags[0]


@varregistry.register_tag("m", VAssemblyVariable)
class VMemoryVariable(VAssemblyVariable):
    """Memory variable with known-location base.

    args[0]: index of memory base in vardictionary
    args[1]: index of memory offset in vardictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VAssemblyVariable.__init__(self, vd, ixval)

    @property
    def base(self) -> VMemoryBase:
        return self.vd.memory_base(self.args[0])

    @property
    def offset(self) -> VMemoryOffset:
        return self.vd.memory_offset(self.args[1])

    @property
    def is_memory_variable(self) -> bool:
        return True

    @property
    def is_global_variable(self) -> bool:
        return self.base.is_global

    def has_global_base(self) -> bool:
        if self.is_global_variable:
            return True
        if self.is_basevar_variable:
            cval = self.basevar.denotation.auxvar
            if cval.is_initial_memory_value:
                return cval.variable.denotation.has_global_base
        return False

    def global_base(self) -> VAssemblyVariable:
        if self.is_global_variable:
            return self
        else:
            cval = self.basevar.denotation.auxvar
            return cval.variable.denotation.global_base()

    @property
    def is_basevar_variable(self) -> bool:
        return self.base.is_basevar

    @property
    def basevar(self) -> "XVariable":
        return self.base.basevar

    @property
    def is_stack_argument(self) -> bool:
        return (self.base.is_local_stack_frame
                and self.offset.is_constant_value_offset
                and self.offset.offsetvalue() > 0)

    def argument_index(self) -> int:
        if self.is_stack_argument:
            return self.offset.offsetvalue() // 4
        else:
            raise UF.CHBError("Assembly variable is not a stack argument: "
                              + str(self))

    @property
    def is_local_stack_variable(self) -> bool:
        return (self.base.is_local_stack_frame
                and self.offset.is_constant_offset
                and self.offset.offsetvalue() < 0)

    @property
    def is_return_address(self) -> bool:
        return (self.base.is_local_stack_frame
                and self.offset.is_constant_offset
                and self.offset.offsetvalue() == 0)

    @property
    def is_realigned_stack_variable(self) -> bool:
        return (self.base.is_realigned_stack_frame
                and self.offset.is_constant_offset
                and self.offset.offsetvalue() <= 0)

    def __str__(self) -> str:
        if self.is_global_variable:
            addr = str(hex(self.offset.offsetvalue()))
            return 'gv_' + str(hex(self.offset.offsetvalue()))
        elif self.is_stack_argument:
            offset = self.offset.offsetvalue()
            return 'arg.' + '{0:04d}'.format(offset)
        elif self.is_local_stack_variable:
            offset = self.offset.offsetvalue()
            return 'var.' + '{0:04d}'.format(-offset)
        elif self.is_return_address:
            return 'var.0000'
        elif self.is_realigned_stack_variable:
            offset = self.offset.offsetvalue()
            return 'varr.' + '{0:04d}'.format(offset)
        return str(str(self.base)) + '[' + str(self.offset) + ']'


@varregistry.register_tag("r", VAssemblyVariable)
class VRegisterVariable(VAssemblyVariable):
    """Register variable.

    args[0]: index of register in bdictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VAssemblyVariable.__init__(self, vd, ixval)

    @property
    def register(self) -> Register:
        return self.bd.register(self.args[0])

    @property
    def is_register_variable(self) -> bool:
        return True

    def __str__(self) -> str:
        return str(self.register)


@varregistry.register_tag("f", VAssemblyVariable)
class VCPUFlagVariable(VAssemblyVariable):
    """CPU flag variable.

    tags[1]: name of flag
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VAssemblyVariable.__init__(self, vd, ixval)

    @property
    def name(self) -> str:
        return self.tags[1]

    @property
    def is_cpu_flag_variable(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.name


@varregistry.register_tag("a", VAssemblyVariable)
class VAuxiliaryVariable(VAssemblyVariable):
    """Auxiliary variable, representing a symbolic constant.

    args[0]: index of constant-value variable in vardictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VAssemblyVariable.__init__(self, vd, ixval)

    @property
    def auxvar(self) -> VConstantValueVariable:
        return self.vd.constant_value_variable(self.args[0])

    def argument_deref_arg_offset(
            self, inbytes: bool = False) -> Tuple[int, int]:
        return self.auxvar.argument_deref_arg_offset(inbytes)

    def call_arguments(self) -> Sequence["XXpr"]:
        return self.auxvar.call_arguments()

    @property
    def is_auxiliary_variable(self) -> bool:
        return True

    @property
    def is_global_value(self) -> bool:
        return self.auxvar.is_global_value

    @property
    def is_stack_base_address(self) -> bool:
        return self.auxvar.is_stack_base_address

    @property
    def is_heap_base_address(self) -> bool:
        return self.auxvar.is_heap_base_address

    @property
    def is_argument_value(self) -> bool:
        return self.auxvar.is_argument_value

    def argument_index(self) -> int:
        if self.is_argument_value:
            return self.auxvar.argument_index()
        else:
            raise UF.CHBError("Variable is not an argument index: " + str(self))

    @property
    def is_argument_deref_value(self) -> bool:
        return self.auxvar.is_argument_deref_value

    @property
    def is_function_return_value(self) -> bool:
        return self.auxvar.is_function_return_value

    @property
    def is_initial_memory_value(self) -> bool:
        return self.auxvar.is_initial_memory_value

    @property
    def is_bridge_variable(self) -> bool:
        return self.auxvar.is_bridge_variable

    @property
    def is_structured_value(self) -> bool:
        return self.auxvar.is_structured_value

    def __str__(self) -> str:
        return str(self.auxvar)
