# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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
"""Assembly variable that is a symbolic constant.

Corresponds to constant_value_variable_t in bchlib/bCHLibTypes:

                                                  tags[0]   tags   args
and constant_value_variable_t =
  | InitialRegisterValue of register_t * int       "ir"       1      2
  | InitialMemoryValue of variable_t               "iv"       1      1
  | FrozenTestValue of                             "ft"       3      1
      variable_t
      * ctxt_iaddress_t
      * ctxt_iaddress_t
  | FunctionReturnValue  of ctxt_iaddress_t        "fr"       2      0
  | SyscallErrorReturnValue of ctxt_iaddress_t     "ev"       2      0
  | FunctionPointer of                             "fp"       2      2
      string
      * string
      * ctxt_iaddress_t
  | CallTargetValue of call_target_t               "ct"       1      1
  | SideEffectValue of                             "se"       2      2
      ctxt_iaddress_t
      * string
      * bool
  | MemoryAddress of int * memory_offset_t         "ma"       1      2
  | BridgeVariable of ctxt_iaddress_t * int        "bv"       2      1
  | FieldValue of string * int * string            "fv"       1      3
  | SymbolicValue of xpr_t                         "sv"       1      1
  | SignedSymbolicValue of int * int * xpr_t      "ssv"       1      3
  | Special of string                              "sp"       1      1
  | RuntimeConstant of string                      "rt"       1      1
  | ChifTemp                                 "chiftemp"       1      0
"""

from typing import Any, Dict, List, Sequence, Tuple, TYPE_CHECKING

from chb.api.CallTarget import CallTarget

from chb.app.Register import Register

from chb.invariants.FnDictionaryRecord import FnVarDictionaryRecord, varregistry
from chb.invariants.VMemoryBase import VMemoryBase
from chb.invariants.VMemoryOffset import VMemoryOffset

from chb.jsoninterface.JSONResult import JSONResult

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.app.Instruction import Instruction
    from chb.invariants.FnVarDictionary import FnVarDictionary
    from chb.invariants.XXpr import XXpr
    from chb.invariants.XVariable import XVariable


class VConstantValueVariable(FnVarDictionaryRecord):

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        FnVarDictionaryRecord.__init__(self, vd, ixval)

    @property
    def is_initial_register_value(self) -> bool:
        return False

    @property
    def is_initial_memory_value(self) -> bool:
        return False

    @property
    def is_frozen_test_value(self) -> bool:
        return False

    @property
    def is_bridge_variable(self) -> bool:
        return False

    @property
    def is_global_value(self) -> bool:
        return False

    @property
    def is_function_return_value(self) -> bool:
        return False

    @property
    def is_symbolic_value(self) -> bool:
        return False

    @property
    def is_signed_symbolic_value(self) -> bool:
        return False

    @property
    def is_function_pointer(self) -> bool:
        return False

    @property
    def is_side_effect_value(self) -> bool:
        return False

    @property
    def is_special_value(self) -> bool:
        return False

    @property
    def is_structured_value(self) -> bool:
        return False

    @property
    def is_stack_base_address(self) -> bool:
        return False

    @property
    def is_heap_base_address(self) -> bool:
        return False

    @property
    def is_argument_value(self) -> bool:
        return False

    @property
    def is_argument_deref_value(self) -> bool:
        return False

    def has_call_target(self) -> bool:
        return False

    @property
    def variable(self) -> "XVariable":
        raise UF.CHBError("Variable property not available on " + str(self))

    @property
    def register(self) -> "Register":
        raise UF.CHBError("Constant value is not an initial register value")

    def argument_deref_arg_offset(self, inbytes: bool = False) -> Tuple[int, int]:
        raise UF.CHBError("argument_deref_arg_offset not supported on "
                          + str(self))

    def argument_index(self) -> int:
        raise UF.CHBError("argument_index not supported on " + str(self))

    def call_target(self) -> CallTarget:
        raise UF.CHBError("call_target not supported on " + str(self))

    def call_arguments(self) -> Sequence["XXpr"]:
        raise UF.CHBError("call_arguments not supported on " + str(self))

    def to_json_result(self) -> JSONResult:
        return JSONResult(
            "auxvariable",
            {},
            "fail",
            "not yet implemented (" + self.tags[0] + ")")

    def __str__(self) -> str:
        return "constant-value-variable:" + self.tags[0]


@varregistry.register_tag("ir", VConstantValueVariable)
class VInitialRegisterValue(VConstantValueVariable):
    """Initial value of register at function entry.

    args[0]: index of register in bdictionary
    args[1]: level (of stack realignment)
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def register(self) -> Register:
        return self.bd.register(self.args[0])

    @property
    def level(self) -> int:
        return self.args[1]

    @property
    def is_initial_register_value(self) -> bool:
        return True

    @property
    def is_stack_base_address(self) -> bool:
        return (
            self.is_arm_stack_base_address
            or self.is_mips_stack_base_address
            or self.is_power_stack_base_address
            or self.is_x86_stack_base_address)

    @property
    def is_mips_stack_base_address(self) -> bool:
        r = self.register
        return r.is_mips_register and r.is_mips_stack_pointer

    @property
    def is_arm_stack_base_address(self) -> bool:
        r = self.register
        return r.is_arm_register and r.is_arm_stack_pointer

    @property
    def is_power_stack_base_address(self) -> bool:
        r = self.register
        return r.is_power_register and r.is_power_stack_pointer

    @property
    def is_x86_stack_base_address(self) -> bool:
        r = self.register
        return r.is_x86_register and r.is_x86_stack_pointer

    @property
    def is_heap_base_address(self) -> bool:
        return False

    @property
    def is_argument_value(self) -> bool:
        return (
            self.is_arm_argument_value
            or self.is_mips_argument_value
            or self.is_power_argument_value)

    @property
    def is_arm_argument_value(self) -> bool:
        r = self.register
        return r.is_arm_register and r.is_arm_argument_register

    @property
    def is_mips_argument_value(self) -> bool:
        r = self.register
        return r.is_mips_register and r.is_mips_argument_register

    @property
    def is_power_argument_value(self) -> bool:
        r = self.register
        return r.is_power_register and r.is_power_argument_register

    def argument_index(self) -> int:
        if self.is_argument_value:
            return self.register.argument_index()
        else:
            raise UF.CHBError(
                "Constant-value-variable is not an argument index: "
                + str(self))

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["register"] = str(self.register)
        content["txtrep"] = self.__str__()
        return JSONResult("auxvariable", content, "ok")

    def __str__(self) -> str:
        if self.level == 0:
            return str(self.register) + "_in"
        else:
            return str(self.register) + "_in_" + str(self.level)


@varregistry.register_tag("iv", VConstantValueVariable)
class VInitialMemoryValue(VConstantValueVariable):
    """Initial value of a memory variable upon function entry.

    args[0]: index of the original variable in xprdictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def variable(self) -> "XVariable":
        return self.xd.variable(self.args[0])

    @property
    def is_initial_memory_value(self) -> bool:
        return True

    @property
    def is_global_value(self) -> bool:
        avar = self.variable.denotation
        return avar.is_memory_variable and avar.is_global_variable

    @property
    def is_argument_value(self) -> bool:
        avar = self.variable.denotation
        return avar.is_memory_variable and avar.is_stack_argument

    @property
    def is_argument_deref_value(self) -> bool:
        avar = self.variable.denotation
        if avar.is_memory_variable and avar.is_basevar_variable:
            xbasevar = avar.basevar
            offset = avar.offset
            return xbasevar.is_argument_value and offset.is_constant_offset
        else:
            return False

    def argument_deref_arg_offset(self, inbytes: bool = False) -> Tuple[int, int]:
        if self.is_argument_deref_value:
            avar = self.variable.denotation
            argindex = avar.basevar.argument_index()
            offset = avar.offset
            if inbytes:
                return (argindex, offset.offsetvalue())
            else:
                return (argindex, offset.offsetvalue() // 4)
        else:
            raise UF.CHBError(
                "Constant-value-variable is not an argument_deref_value: "
                + str(self))

    def argument_index(self) -> int:
        if self.is_argument_value:
            return self.variable.argument_index()
        else:
            raise UF.CHBError("Constant-value-variable is not an argument: "
                              + str(self))

    @property
    def is_structured_value(self) -> bool:
        return self.variable.is_structured_var

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        memvar = self.variable.to_json_result()
        if memvar.is_ok:
            content["memvar"] = memvar.content
            content["txtrep"] = self.__str__()
            return JSONResult("auxvariable", content, "ok")
        else:
            return JSONResult("auxvariable", {}, "fail", memvar.reason)

    def __str__(self) -> str:
        return str(self.variable.denotation) + '_in'


@varregistry.register_tag("ft", VConstantValueVariable)
class VFrozenTestValue(VConstantValueVariable):
    """Value of a test at an earlier instruction.

    tags[1]: address of test instruction
    tags[2]: address of conditional jump instruction
    args[0]: index of variable in xprdictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def variable(self) -> "XVariable":
        return self.xd.variable(self.args[0])

    @property
    def test_addr(self) -> str:
        return self.tags[1]

    @property
    def jump_addr(self) -> str:
        return self.tags[2]

    @property
    def is_frozen_test_value(self) -> bool:
        return True

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["testaddr"] = self.test_addr
        content["jumpaddr"] = self.jump_addr
        jtestvar = self.variable.to_json_result()
        if jtestvar.is_ok:
            content["testvar"] = jtestvar.content
            content["txtrep"] = str(self)
            return JSONResult("frozentestvar", content, "ok")
        else:
            return JSONResult(
                "frozentestvar",
                {},
                "fail",
                "frozentestvar: " + str(jtestvar.reason))

    def __str__(self) -> str:
        return (str(self.variable)
                + '_@val_' + str(self.test_addr)
                + '_@_' + str(self.jump_addr))


@varregistry.register_tag("bv", VConstantValueVariable)
class VBridgeVariable(VConstantValueVariable):
    """Variable that represents a call argument.

    tags[1]: address of call site
    args[0]: argument index
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def callsite(self) -> str:
        return self.tags[1]

    @property
    def is_bridge_variable(self) -> bool:
        return True

    def __str__(self) -> str:
        return "bridge-from(" + self.callsite + ")"


@varregistry.register_tag("fr", VConstantValueVariable)
class VFunctionReturnValue(VConstantValueVariable):
    """Symbolic representation of the return value of a function.

    tags[1]: address of call site
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def callsite(self) -> str:
        return self.tags[1]

    @property
    def is_function_return_value(self) -> bool:
        return True

    @property
    def is_heap_base_address(self) -> bool:
        return (
            self.has_call_target()
            and str(self.call_target()) == "malloc")

    def call_instruction(self) -> "Instruction":
        return self.function.instruction(self.callsite)

    def call_arguments(self) -> Sequence["XXpr"]:
        return self.call_instruction().call_arguments

    def has_call_target(self) -> bool:
        return self.finfo.has_call_target(self.callsite)

    def call_target(self) -> CallTarget:
        return self.finfo.call_target(self.callsite)

    def to_json_result(self) -> JSONResult:
        content: Dict[str, Any] = {}
        content["callsite"] = self.callsite
        content["calltarget"] = str(self.call_target())
        content["txtrep"] = self.__str__()
        return JSONResult("auxvariable", content, "ok")

    def __str__(self) -> str:
        if self.has_call_target():
            tgtval = self.call_target()
            if str(tgtval) == "getenv":
                if len(self.call_arguments()) > 0:
                    args = str(self.call_arguments()[0])
                    return "rtn_" + self.callsite + "_getenv(" + args + ")"
                else:
                    return "rtn_" + self.callsite + "_" + str(tgtval)
            else:
                return "rtn_" + self.callsite + "_" + tgtval.name
        else:
            return "rtn_" + self.callsite


@varregistry.register_tag("fp", VConstantValueVariable)
class FunctionPointer(VConstantValueVariable):
    """Function pointer.

    tags[0]: address of creation
    args[0]: index of name of function in bdictionary
    args[1]: index of name of creator in bdictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def name(self) -> str:
        return self.bd.string(self.args[0])

    @property
    def creator(self) -> str:
        return self.bd.string(self.args[1])

    @property
    def creation_addr(self) -> str:
        return self.tags[1]

    @property
    def is_function_pointer(self) -> bool:
        return True

    def __str__(self) -> str:
        return "fp:" + self.creator + ":" + self.name + "@" + self.creation_addr


@varregistry.register_tag("ma", VConstantValueVariable)
class MemoryAddress(VConstantValueVariable):
    """Address of memory variable.

    args[0]: index of memory base in vardictionary
    args[1]: index of memory offset in vardictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def base(self) -> VMemoryBase:
        return self.vd.memory_base(self.args[0])

    @property
    def offset(self) -> VMemoryOffset:
        return self.vd.memory_offset(self.args[1])

    def __str__(self) -> str:
        return str(self.base) + " + " + str(self.offset)


@varregistry.register_tag("fv", VConstantValueVariable)
class FieldValue(VConstantValueVariable):
    """Symbolic representation of a field in a struct.

    args[0]: index of name of struct in bdictionary
    args[1]: offset of field within struct (in bytes)
    args[2]: index of name of field in bdictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def structname(self) -> str:
        return self.bd.string(self.args[0])

    @property
    def fieldname(self) -> str:
        return self.bd.string(self.args[2])

    @property
    def fieldoffset(self) -> int:
        return self.args[1]

    def __str__(self) -> str:
        return self.structname + "." + self.fieldname + "@" + str(self.fieldoffset)


@varregistry.register_tag("ct", VConstantValueVariable)
class CallTargetValue(VConstantValueVariable):
    """Symbolic representation of a call target.

    args[0]: index of call target in interfacedictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def calltarget(self) -> CallTarget:
        return self.ixd.call_target(self.args[0])

    def __str__(self) -> str:
        return "call_target:" + str(self.calltarget)


@varregistry.register_tag("se", VConstantValueVariable)
class SideEffectValue(VConstantValueVariable):
    """Symbolic representation of a side-effect of a function call.

    tags[1]: callsite
    args[0]: index of argument description in bdictionary
    args[1]: 1 if global, 0 otherwise
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def callsite(self) -> str:
        return self.tags[1]

    @property
    def argument_desc(self) -> str:
        return self.bd.string(self.args[0])

    @property
    def is_global(self) -> bool:
        return self.args[1] == 1

    @property
    def is_side_effect_value(self) -> bool:
        return True

    def has_call_target(self) -> bool:
        return self.finfo.has_call_target(self.callsite)

    def call_target(self) -> CallTarget:
        if self.has_call_target():
            return self.finfo.call_target(self.callsite)
        else:
            raise UF.CHBError("Side-effect value does not have a call target.")

    def __str__(self) -> str:
        if self.has_call_target():
            return 'se_' + str(self.call_target()) + '_' + self.argument_desc
        else:
            return 'se_' + str(self.callsite) + '_' + self.argument_desc


@varregistry.register_tag("sv", VConstantValueVariable)
class SymbolicValue(VConstantValueVariable):
    """Symbolic representation of an expression.

    args[0]: index of expression in xprdictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def expr(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    @property
    def is_symbolic_value(self) -> bool:
        return True

    def to_json_result(self) -> JSONResult:
        jexp = self.expr.to_json_result()
        if jexp.is_ok:
            content: Dict[str, Any] = {}
            content["symbolic-expr"] = jexp.content
            content["txtrep"] = str(self)
            return JSONResult("auxvariable", content, "ok")
        else:
            return JSONResult("auxvariable", {}, "fail", str(jexp.reason))

    def __str__(self) -> str:
        return str(self.expr)


@varregistry.register_tag("ssv", VConstantValueVariable)
class SignedSymbolicValue(VConstantValueVariable):
    """Symbolic representation of a sign-extended expression.

    args[0]: index of expression in xprdictionary
    args[1]: original size of expression (in bits)
    args[2]: sign-extended size of expression (in bits)
    """

    @property
    def expr(self) -> "XXpr":
        return self.xd.xpr(self.args[0])

    @property
    def originalsize(self) -> int:
        return self.args[1]

    @property
    def extendedsize(self) -> int:
        return self.args[2]

    @property
    def is_signed_symbolic_value(self) -> bool:
        return True

    def __str__(self) -> str:
        return (
            str(self.expr)
            + "["
            + str(self.originalsize)
            + ">"
            + str(self.extendedsize))


@varregistry.register_tag("rt", VConstantValueVariable)
class RuntimeConstant(VConstantValueVariable):
    """Runtime constant with unknown value.

    args[0]: index of unique identifier in bdictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def identifier(self) -> str:
        return self.bd.string(self.args[0])

    @property
    def is_runtime_constant(self) -> bool:
        return True

    def __str__(self) -> str:
        return "runtime-constant:" + self.identifier


@varregistry.register_tag("sp", VConstantValueVariable)
class SpecialValue(VConstantValueVariable):
    """Named symbolic value.

    args[0]: index of name in bdictionary
    """

    def __init__(
            self,
            vd: "FnVarDictionary",
            ixval: IndexedTableValue) -> None:
        VConstantValueVariable.__init__(self, vd, ixval)

    @property
    def name(self) -> str:
        return self.bd.string(self.args[0])

    @property
    def is_special_value(self) -> bool:
        return True

    def __str__(self) -> str:
        return "special-value:" + self.name
