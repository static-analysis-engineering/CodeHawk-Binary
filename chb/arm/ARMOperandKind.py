# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2024  Aarno Labs LLC
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
"""Different types of operand of an ARM assembly instruction.

Corresponds to arm_operand_kind_t in bchlibarm32/BCHARMTypes

                                                    tags[0]   tags         args
type arm_operand_kind_t =
  | ARMDMBOption of dmb_option_t                      "d"       2            0
  | ARMCPSEffect of cps_effect_t                     "ce"       2            0
  | ARMInterruptFlags of interrupt_flags_t           "if"       2            0
  | ARMReg of arm_reg_t                               "r"       2            0
  | ARMDoubleReg of arm_reg_t * arm_reg_t             "dr"      3            0
  | ARMWritebackReg of bool * arm_reg_t * int option "wr"       2            2
  | ARMSpecialReg of arm_special_reg_t               "sr"       2            0
  | ARMExtensionReg of arm_extension_register_t      "xr"       1            1
  | ARMDoubleExtensionReg of                         "dxr"      1            2
       arm_extension_register_t
       * arm_extension_register_t
  | ARMExtensionRegElement of
       arm_extension_register_element_t              "xre"      1            1
  | ARMRegList of arm_reg_t list                      "l"     1+len(regs)    0
  | ARMExtensionRegList of
       arm_extension_register_list_t                 "xl"       1            1
  | ARMSIMDList of arm_simd_list_element_t list     "simdl"     1           len
  | ARMShiftedReg of                                  "s"       2            1
     arm_reg_t
     * register_shift_rotate_t
  | ARMRegBitSequence of arm_reg_t * int * int        "b"       2            2
     (* lsb, widthm1 *)
  | ARMImmediate of immediate_int                     "i"       2            0
  | ARMAbsolute of doubleword_int                     "a"       1            1
  | ARMLiteralAddress of doubleword_int               "p"       1            1
  | ARMMemMultiple of arm_reg_t * int                 "m"       2            1
     (* number of locations *)
  | ARMOffsetAddress of                               "o"       2            4
      arm_reg_t  (* base register *)
      * arm_memory_offset_t (* offset *)
      * bool (* isadd *)
      * bool (* iswback *)
      * bool (* isindex *)
  | ARMSIMDAddress of                                "simda"    2            2
      arm_reg_t  (* base register *)
      * int      (* alignment *)
      * arm_simd_writeback_t (* writeback mode *)
  | ARMFPConstant of float                            "c"       2            0
"""

from typing import cast, List, Optional, Tuple, TYPE_CHECKING

from chb.arm.ARMDictionaryRecord import ARMDictionaryRecord, armregistry

import chb.ast.ASTNode as AST
from chb.astinterface.ASTInterface import ASTInterface

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.app.BDictionary import BDictionary, AsmAddress
    from chb.app.ARMExtensionRegister import (
        ARMExtensionRegister, ARMExtensionRegisterElement)
    from chb.arm.ARMDictionary import ARMDictionary
    from chb.arm.ARMMemoryOffset import ARMMemoryOffset, ARMImmOffset
    from chb.arm.ARMShiftRotate import ARMShiftRotate, ARMImmSRT, ARMRegSRT
    from chb.arm.ARMSIMD import ARMSIMDWriteback, ARMSIMDListElement


class ARMOperandKind(ARMDictionaryRecord):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)

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
    def is_fp_constant(self) -> bool:
        return False

    @property
    def is_register(self) -> bool:
        return False

    @property
    def is_double_register(self) -> bool:
        return False

    @property
    def is_extension_register(self) -> bool:
        return False

    @property
    def is_double_extension_register(self) -> bool:
        return False

    @property
    def is_special_register(self) -> bool:
        return False

    @property
    def is_shifted_register(self) -> bool:
        return False

    @property
    def register(self) -> str:
        raise UF.CHBError("Register not available for operand kind " + str(self))

    @property
    def is_indirect_register(self) -> bool:
        return False

    @property
    def indirect_register(self) -> str:
        raise UF.CHBError(
            "Indirect register not available for operand kind " + str(self))

    @property
    def is_write_back(self) -> bool:
        return False

    @property
    def is_register_list(self) -> bool:
        return False

    @property
    def registers(self) -> List[str]:
        raise UF.CHBError("Operand is not a register list " + str(self))

    @property
    def is_extension_register_list(self) -> bool:
        return False

    @property
    def offset(self) -> int:
        raise UF.CHBError("Offset not avaialable for operand kind " + str(self))

    @property
    def value(self) -> int:
        raise UF.CHBError("Value not available for operand kind " + str(self))

    @property
    def scale_factor(self) -> Optional[int]:
        raise UF.CHBError(
            "Scale factor not available for operand kind " + str(self))

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        raise UF.CHBError(
            "AST lvalue not available for operand kind "
            + self.tags[0]
            + "("
            + str(self)
            + ")")

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        raise UF.CHBError(
            "AST rvalue not available for operand kind "
            + self.tags[0]
            + "("
            + str(self)
            + ")")

    def __str__(self) -> str:
        return "operandkind: " + self.tags[0]


@armregistry.register_tag("r", ARMOperandKind)
class ARMRegisterOp(ARMOperandKind):
    """Regular register.

    tags[1]: name of register
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def is_register(self) -> bool:
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


@armregistry.register_tag("dr", ARMOperandKind)
class ARMDoubleRegisterOp(ARMOperandKind):
    """Two registers that act as a single operand.

    tags[1]: name of first register
    tags[2]: name of second register
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def register1(self) -> str:
        return self.tags[1]

    @property
    def register2(self) -> str:
        return self.tags[2]

    @property
    def is_double_register(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return self.register1 + "_" + self.register2

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_lval(self.name, vtype=vtype), [], [])

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_expr(self.name, vtype=vtype), [], [])

    def __str__(self) -> str:
        return self.name


@armregistry.register_tag("sr", ARMOperandKind)
class ARMSpecialRegisterOp(ARMOperandKind):
    """Special register (e.g., processor status word).

    tags[1]: name of register
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def is_special_register(self) -> bool:
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


@armregistry.register_tag("xr", ARMOperandKind)
class ARMExtensionRegisterOp(ARMOperandKind):
    """ARM extension register (floating point or vector)

    tags[1]: arm_extension_reg_type (S, D, or Q)
    args[0]: index register index (0..31)
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def xregister(self) -> "ARMExtensionRegister":
        return self.bd.arm_extension_register(self.args[0])

    @property
    def is_single(self) -> bool:
        return self.xregister.is_single

    @property
    def is_double(self) -> bool:
        return self.xregister.is_double

    @property
    def is_quad(self) -> bool:
        return self.xregister.is_quad

    @property
    def size(self) -> int:
        if self.is_single:
            return 32
        elif self.is_double:
            return 64
        else:
            return 128

    @property
    def index(self) -> int:
        return self.xregister.regindex

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_lval(str(self.xregister), vtype=vtype),
            [],
            [])

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_expr(str(self.xregister), vtype=vtype),
            [],
            [])

    def __str__(self) -> str:
        return str(self.xregister)



@armregistry.register_tag("dxr", ARMOperandKind)
class ARMDoubleExtensionRegisterOp(ARMOperandKind):
    """ARM extension register (floating point or vector)

    tags[1]: arm_extension_reg_type (S, D, or Q)
    args[0]: index of first register in bdictionary
    args[1]: index of second register in bdictionary
    """

    def __init__(self, d: "ARMDictionary", ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def xregister1(self) -> "ARMExtensionRegister":
        return self.bd.arm_extension_register(self.args[0])

    @property
    def xregister2(self) -> "ARMExtensionRegister":
        return self.bd.arm_extension_register(self.args[0])

    @property
    def is_single(self) -> bool:
        return self.xregister1.is_single

    @property
    def is_double(self) -> bool:
        return self.xregister1.is_double

    @property
    def is_quad(self) -> bool:
        return self.xregister1.is_quad

    @property
    def size(self) -> int:
        if self.is_single:
            return 64
        elif self.is_double:
            return 128
        else:
            return 256

    @property
    def index1(self) -> int:
        return self.xregister1.regindex

    @property
    def index2(self) -> int:
        return self.xregister2.regindex

    @property
    def name(self) -> str:
        return str(self.xregister1) + "_" + str(self.xregister2)

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_lval(self.name, vtype=vtype), [], [])

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (
            astree.mk_register_variable_expr(self.name, vtype=vtype), [], [])

    def __str__(self) -> str:
        return str(self.name)


@armregistry.register_tag("xre", ARMOperandKind)
class ARMExtensionRegElementOp(ARMOperandKind):
    """ARM extension register element.

    args[0]: index of arm-extension-register element
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def xregelement(self) -> "ARMExtensionRegisterElement":
        return self.bd.arm_extension_register_element(self.args[0])

    def __str__(self) -> str:
        return str(self.xregelement)


@armregistry.register_tag("l", ARMOperandKind)
class ARMRegListOp(ARMOperandKind):
    """List of regular registers.

    tags[1...]: names of registers
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def registers(self) -> List[str]:
        return self.tags[1:]

    @property
    def count(self) -> int:
        return len(self.registers)

    @property
    def is_register_list(self) -> bool:
        return True

    def __str__(self) -> str:
        return "{" + ",".join(self.registers) + "}"


@armregistry.register_tag("xl", ARMOperandKind)
class ARMExtensionRegListOp(ARMOperandKind):
    """List of extension registers.

    args: indices of extension registers
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def extension_registers(self) -> List["ARMExtensionRegister"]:
        return [self.bd.arm_extension_register(i) for i in self.args]

    @property
    def is_extension_register_list(self) -> bool:
        return True

    @property
    def count(self) -> int:
        return len(self.extension_registers)

    def __str__(self) -> str:
        return "{" + ",".join(str(r) for r in self.extension_registers) + "}"


@armregistry.register_tag("s", ARMOperandKind)
class ARMShiftedRegisterOp(ARMOperandKind):
    """Value of register shifted by a certain amount.

    tags[1]: name of register
    args[0]: index of register-shift-rotate in armdictionary
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def is_shifted_register(self) -> bool:
        return True

    @property
    def shift_rotate(self) -> "ARMShiftRotate":
        return self.armd.arm_register_shift(self.args[0])

    @property
    def scale_factor(self) -> Optional[int]:
        srt = self.shift_rotate
        if srt.is_imm_srt:
            srt = cast("ARMImmSRT", srt)
            shiftamount = srt.shift_amount
            if shiftamount == 0:
                return 1
            else:
                if srt.is_shift_left:
                    return 2 ** shiftamount
                else:
                    return None
        else:
            return None

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        raise UF.CHBError(
            "AST lvalue unexpected for shifted register " + str(self))

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        srt = self.shift_rotate
        rvar = astree.mk_register_variable_expr(self.register, vtype=vtype)
        if srt.is_imm_srt:
            srt = cast("ARMImmSRT", srt)
            shiftamount = srt.shift_amount
            if shiftamount == 0:
                return (rvar, [], [])
            else:
                shiftoperand = astree.mk_integer_constant(shiftamount)
                if srt.is_shift_left:
                    xpr = astree.mk_binary_op("lsl", rvar, shiftoperand)
                elif srt.is_logical_shift_right:
                    xpr = astree.mk_binary_op("lsr", rvar, shiftoperand)
                elif srt.is_arithmetic_shift_right:
                    xpr = astree.mk_binary_op("asr", rvar, shiftoperand)
                else:
                    raise UF.CHBError(
                        "Shifted register operand "
                        + str(self)
                        + " not yet supported")
        elif srt.is_reg_srt:
            srt = cast ("ARMRegSRT", srt)
            shiftregop = (
                astree.mk_register_variable_expr(
                    srt.register, vtype=astree.astree.int_type))
            if srt.is_shift_left:
                xpr = astree.mk_binary_op("lsl", rvar, shiftregop)
            elif srt.is_logical_shift_right:
                xpr = astree.mk_binary_op("lsr", rvar, shiftregop)
            elif srt.is_arithmetic_shift_right:
                xpr = astree.mk_binary_op("asr", rvar, shiftregop)
            else:
                raise UF.CHBError(
                    "Shifted register operand "
                    + str(self)
                    + " not yet supported")

        else:
            raise UF.CHBError(
                "Shifted register operand " + str(self) + " not yet supported")

        return (xpr, [], [])

    def __str__(self) -> str:
        srt = str(self.shift_rotate)
        if srt == "":
            return self.register
        else:
            return self.register + "," + srt


@armregistry.register_tag("b", ARMOperandKind)
class ARMRegBitSequenceOp(ARMOperandKind):
    """Sequence of bits in a register value.

    tags[1]: name of register
    args[0]: position of least significant bit
    args[1]: width of the bit sequence
    """

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def lsb(self) -> int:
        return self.args[0]

    @property
    def width(self) -> int:
        return self.args[1] + 1

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        raise UF.CHBError(
            "AST lvalue unexpected for bit sequende operand " + str(self))

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        """
        from: https://stackoverflow.com/questions/8366625/arm-bit-field-extract

        dest = (src >> lsb) & ((1 << width) - 1);
        """
        rvar = astree.mk_register_variable_expr(self.register, vtype=vtype)
        width = self.width
        lsb = self.lsb

        mask = astree.mk_integer_constant(1 << width)
        if lsb == 0:
            xpr = astree.mk_binary_op("band", rvar, mask)
        else:
            shiftamount = astree.mk_integer_constant(lsb)
            xprsub = astree.mk_binary_op("lsr", rvar, shiftamount)
            xpr = astree.mk_binary_op("band", xprsub, mask)

        return (xpr, [], [])

    def __str__(self) -> str:
        return self.register + ", #" + str(self.lsb) + ", #" + str(self.width)


@armregistry.register_tag("a", ARMOperandKind)
class ARMAbsoluteOp(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

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


@armregistry.register_tag("p", ARMOperandKind)
class ARMLiteralAddressOp(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def address(self) -> "AsmAddress":
        return self.bd.address(self.args[0])

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        gvname = "gv_" + self.address.get_hex()
        gv = astree.mk_global_variable_expr(
            gvname,
            vtype=vtype,
            globaladdress=self.address.get_int(),
            llref=True)
        return (gv, [], [])

    def __str__(self) -> str:
        return str(self.address)


@armregistry.register_tag("m", ARMOperandKind)
class ARMMemMultipleOp(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def count(self) -> int:
        return self.args[1]

    def __str__(self) -> str:
        return self.register


@armregistry.register_tag("o", ARMOperandKind)
class ARMOffsetAddressOp(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def register(self) -> str:
        return self.tags[1]

    @property
    def indirect_register(self) -> str:
        return self.register

    @property
    def align(self) -> int:
        return self.args[0]

    @property
    def memory_offset(self) -> "ARMMemoryOffset":
        return self.armd.arm_memory_offset(self.args[1])

    def has_immediate_memory_offset(self) -> bool:
        return self.memory_offset.is_immediate

    def has_zero_immediate_memory_offset(self) -> bool:
        if self.has_immediate_memory_offset():
            offset = cast("ARMImmOffset", self.memory_offset)
            return offset.is_zero
        else:
            return False

    @property
    def is_indirect_register(self) -> bool:
        return True

    @property
    def is_add(self) -> bool:
        return self.args[2] == 1

    @property
    def is_write_back(self) -> bool:
        return self.args[3] == 1

    @property
    def is_index(self) -> bool:
        return self.args[4] == 1

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        offset = self.memory_offset.ast_rvalue(astree)
        if not self.is_add:
            offset = astree.mk_unary_op("minus", offset)
        xreg = astree.mk_register_variable_expr(self.register, vtype=vtype)
        xindex = astree.mk_binary_op("plus", xreg, offset)

        if self.is_write_back:
            reglv = astree.mk_variable_lval(self.register)
            assign = astree.mk_assign(reglv, xindex)
            if self.is_index:
                memexp = astree.mk_memref_lval(xindex)
                return (memexp, [], [assign])
            else:
                memexp = astree.mk_memref_lval(xreg)
                return (memexp, [], [assign])
        else:
            memexp = astree.mk_memref_lval(xindex)
            return (memexp, [], [])

    def ast_addr_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> AST.ASTExpr:
        xreg = astree.mk_register_variable_expr(self.register, vtype=vtype)
        offset = self.memory_offset.ast_rvalue(astree)
        if not self.is_add:
            return astree.mk_binary_op("minus", xreg, offset)
        else:
            return astree.mk_binary_op("plus", xreg, offset)

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        (lval, preinstrs, postinstrs) = self.ast_lvalue(astree, vtype=vtype)
        rval = astree.mk_lval_expr(lval)
        return (rval, preinstrs, postinstrs)

    def __str__(self) -> str:
        memoffset = str(self.memory_offset)
        if not self.is_add:
            memoffset = "-" + memoffset
        if self.is_write_back:
            if self.is_index:
                if self.has_zero_immediate_memory_offset():
                    return "[" + self.register + "]!"
                else:
                    return "[" + self.register + "," + memoffset + "]!"
            else:
                return "[" + self.register + "]," + memoffset
        else:
            if self.has_zero_immediate_memory_offset():
                return "[" + self.register + "]"
            else:
                return "[" + self.register + "," + memoffset + "]"


@armregistry.register_tag("i", ARMOperandKind)
class ARMImmediateOp(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def value(self) -> int:
        return int(self.tags[1])

    def to_unsigned_int(self) -> int:
        return self.value

    def to_signed_int(self) -> int:
        return self.value

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
        if self.value >= 10 or self.value <= -10:
            return "#" + hex(self.value)
        else:
            return "#" + str(self.value)


@armregistry.register_tag("c", ARMOperandKind)
class ARMFPConstant(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def floatvalue(self) -> float:
        return float(self.tags[1])

    @property
    def is_fp_constant(self) -> bool:
        return True

    def ast_lvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTLval, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        raise UF.CHBError("Floating point constant cannot be an lvalue")

    def ast_rvalue(
            self,
            astree: ASTInterface,
            vtype: Optional[AST.ASTTyp] = None) -> Tuple[
                AST.ASTExpr, List[AST.ASTInstruction], List[AST.ASTInstruction]]:
        return (astree.mk_float_constant(self.floatvalue), [], [])

    def __str__(self) -> str:
        return str(self.floatvalue)


@armregistry.register_tag("d", ARMOperandKind)
class ARMDMBOption(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    def __str__(self) -> str:
        return self.tags[1]


@armregistry.register_tag("simdl", ARMOperandKind)
class ARMSIMDList(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def elements(self) -> List["ARMSIMDListElement"]:
        return [self.armd.arm_simd_list_element(i) for i in self.args]

    def __str__(self) -> str:
        return "{" + ",".join(str(e) for e in self.elements) + "}"


@armregistry.register_tag("simda", ARMOperandKind)
class ARMSIMDAddress(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def baseregister(self) -> str:
        return self.tags[1]

    @property
    def alignment(self) -> int:
        return self.args[0]

    @property
    def writeback(self) -> "ARMSIMDWriteback":
        return self.armd.arm_simd_writeback(self.args[1])

    def __str__(self) -> str:
        wb = self.writeback
        palign = "" if self.alignment == 1 else ":" + str(self.alignment)
        pbase = self.baseregister
        if wb.is_no_writeback:
            return "[" + pbase + palign + "]"
        elif wb.is_bytes_transferred:
            return "[" + pbase + palign + "]!"
        else:
            return "[" + pbase + palign + "], " + str(wb)


@armregistry.register_tag("ce", ARMOperandKind)
class ARMCPSEffect(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def effect(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return self.effect


@armregistry.register_tag("if", ARMOperandKind)
class ARMInterruptFlags(ARMOperandKind):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMOperandKind.__init__(self, d, ixval)

    @property
    def interruptflags(self) -> str:
        return self.tags[1]

    def __str__(self) -> str:
        return self.interruptflags
