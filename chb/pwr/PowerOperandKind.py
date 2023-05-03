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
"""Different types of operand of a Power assembly instruction.

Corresponds to pwr_operand_kind_t in bchlibpower32/BCHPowerTypes

                                                         tags[0]    tags    args
type pwr_operand_kind_t =
  | PowerGPReg of int                                      "g"        1       1
  | PowerSpecialReg of pwr_special_reg_t                   "s"        2       0
  | PowerRegisterField of pwr_register_field_t             "f"        2       0
  | PowerConditionRegisterBit of int                       "c"        1       1
  | PowerImmediate of immediate_int                        "i"        2       0
  | PowerAbsolute of doubleword_int                        "a"        1       1
  | PowerIndReg of int * numerical_t                       "ir"       2       1
  | PowerIndexedIndReg of int * int                        "xr"       1       2
"""

from typing import cast, List, Optional, Tuple, TYPE_CHECKING

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.util.fileutil as UF
from chb.util.IndexedTable import IndexedTableValue

from chb.pwr.PowerDictionaryRecord import PowerDictionaryRecord, pwrregistry

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary, AsmAddress
    from chb.pwr.PowerDictionary import PowerDictionary


class PowerOperandKind(PowerDictionaryRecord):

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerDictionaryRecord.__init__(self, pwrd, ixval)

    @property
    def size(self) -> int:
        return 4

    @property
    def is_absolute(self) -> bool:
        return False

    @property
    def is_immediate(self) -> bool:
        return False

    @property
    def is_register(self) -> bool:
        return False

    @property
    def is_special_register(self) -> bool:
        return False

    @property
    def is_register_field(self) -> bool:
        return False

    @property
    def is_condition_register_bit(self) -> bool:
        return False

    @property
    def is_indirect_register(self) -> bool:
        return False

    @property
    def is_indexed_indirect_register(self) -> bool:
        return False

    @property
    def register(self) -> str:
        raise UF.CHBError("Operand is not a register: " + str(self))

    @property
    def indirect_register(self) -> str:
        raise UF.CHBError("Operand is not a direct register: " + str(self))

    @property
    def offset(self) -> int:
        raise UF.CHBError("Operand does not have an offset: " + str(self))

    @property
    def value(self) -> int:
        raise UF.CHBError("Operand does not have a value: " + str(self))

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_lval(str(self.register), vtype=vtype),
            [],
            [])

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_expr(str(self.register), vtype=vtype),
            [],
            [])

    def __str__(self) -> str:
        return "operandkind: " + self.tags[0]


@pwrregistry.register_tag("g", PowerOperandKind)
class PowerGPRegisterOp(PowerOperandKind):
    """General-purpose register.

    args[0]: index of register (0 .. 31)
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOperandKind.__init__(self, pwrd, ixval)

    @property
    def index(self) -> int:
        return self.args[0]

    @property
    def register(self) -> str:
        return "r" + str(self.index)

    @property
    def is_register(self) -> bool:
        return True

    @property
    def is_gp_register(self) -> bool:
        return True

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_lval(self.register, vtype=vtype), [], [])

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_expr(self.register, vtype=vtype), [], [])

    def __str__(self) -> str:
        return self.register


@pwrregistry.register_tag("s", PowerOperandKind)
class PowerSpecialRegisterOp(PowerOperandKind):
    """Special-purpose register.

    tags[1]: name of the register
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOperandKind.__init__(self, pwrd, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def is_register(self) -> bool:
        return True

    @property
    def is_sp_register(self) -> bool:
        return True

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_lval(self.register, vtype=vtype), [], [])

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_expr(self.register, vtype=vtype), [], [])

    def __str__(self) -> str:
        return self.register


@pwrregistry.register_tag("f", PowerOperandKind)
class PowerRegisterFieldOp(PowerOperandKind):
    """A named contiguous sequence of bits in a special register.

    tags[1]: name of the field
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOperandKind.__init__(self, pwrd, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def is_register(self) -> bool:
        return True

    @property
    def is_register_field(self) -> bool:
        return True

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_lval(self.register, vtype=vtype), [], [])

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_expr(self.register, vtype=vtype), [], [])

    def __str__(self) -> str:
        return self.register
    

@pwrregistry.register_tag("c", PowerOperandKind)
class PowerConditionRegisterBitOp(PowerOperandKind):
    """A given bit in the condition register.

    args[0]: index of bit in condition register
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOperandKind.__init__(self, pwrd, ixval)

    @property
    def index(self) -> int:
        return self.args[0]

    @property
    def is_condition_register_bit(self) -> bool:
        return True

    def __str__(self) -> str:
        return "cr" + str(self.index)


@pwrregistry.register_tag("i", PowerOperandKind)
class PowerImmediateOp(PowerOperandKind):
    """Immediate value (signed/unsigned).

    tags[1]: immediate value (represented as string)
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOperandKind.__init__(self, pwrd, ixval)

    @property
    def value(self) -> int:
        return int(self.tags[1])

    @property
    def is_immediate(self) -> bool:
        return True

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        raise UF.CHBError("Immediate operand cannot be an lvalue")

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (astree.mk_integer_constant(self.value), [], [])

    def __str__(self) -> str:
        return str(self.value)


@pwrregistry.register_tag("a", PowerOperandKind)
class PowerAbsoluteOp(PowerOperandKind):
    """Absolute address.

    args[0]: index of address in bdictionary
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOperandKind.__init__(self, pwrd, ixval)

    @property
    def address(self) -> "AsmAddress":
        return self.bd.address(self.args[0])

    @property
    def is_absolute(self) -> bool:
        return True

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (astree.mk_integer_constant(self.address.get_int()), [], [])

    def __str__(self) -> str:
        return str(self.address)


@pwrregistry.register_tag("ir", PowerOperandKind)
class PowerIndRegOp(PowerOperandKind):
    """Indirect register

    tags[1]: offset (string representation)
    args[0]: index of general-purpose register
    """

    def __init__(self, pwrd: "PowerDictionary", ixval: IndexedTableValue) -> None:
        PowerOperandKind.__init__(self, pwrd, ixval)

    @property
    def register(self) -> str:
        return "r" + str(self.args[0])

    @property
    def offset(self) -> int:
        return int(self.tags[1])

    @property
    def is_indirect_register(self) -> bool:
        return True

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        xreg = astree.mk_register_variable_expr(self.register, vtype=vtype)
        xoffset = astree.mk_integer_constant(self.offset)
        xindex = astree.mk_binary_op("plus", xreg, xoffset)
        memexp = astree.mk_memref_lval(xindex)
        return (memexp, [], [])

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        (lval, preinstrs, postinstrs) = self.ast_lvalue(astree, vtype=vtype)
        rval = astree.mk_lval_expr(lval)
        return (rval, preinstrs, postinstrs)

    def __str__(self) -> str:
        return hex(self.offset) + "(" + self.register + ")"
