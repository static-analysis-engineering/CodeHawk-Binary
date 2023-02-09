# ------------------------------------------------------------------------------
# PIR: Patching Intermediate Representation
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2023  Aarno Labs, LLC
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

from typing import List, NoReturn, Tuple

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree, voidtype

import chb.ast.ASTNode as AST

from chb.ast.ASTApplicationInterface import ASTApplicationInterface
from chb.ast.ASTCPrettyPrinter import ASTCPrettyPrinter
from chb.ast.ASTSymbolTable import ASTGlobalSymbolTable, ASTLocalSymbolTable


class ASTreeSetup:

    def __init__(self, name: str, faddr="0x0") -> None:
        self._astapi = ASTApplicationInterface()
        self._localsymboltable = ASTLocalSymbolTable(
            self._astapi.globalsymboltable)
        self._astree = AbstractSyntaxTree(faddr, name, self._localsymboltable)

    @property
    def astree(self) -> AbstractSyntaxTree:
        return self._astree

    def stmtstr(self, title: str, stmt: AST.ASTStmt) -> str:
        lines: List[str] = []
        lines.append("~" * 80)
        lines.append(title)
        pp = ASTCPrettyPrinter(self._localsymboltable)
        lines.append(pp.to_c(stmt))
        lines.append("=" * 80)
        return "\n".join(lines)                 
        

def strb_low_level () -> None:

    # STRB           R12, [R3, #0x411]

    astapi = ASTreeSetup("strb_1")
    astree = astapi.astree

    r3type = astree.mk_pointer_type(astree.unsigned_char_type)
    r3 = astree.mk_named_lval_expression("R3", vtype=r3type)
    offset = astree.mk_integer_constant(int("0x411", 16))
    r3deref = astree.mk_memref_lval(astree.mk_plus_expression(r3, offset))
    r12 = astree.mk_named_lval_expression("R12", vtype=astree.unsigned_char_type)

    assignment = astree.mk_assign(r3deref, r12)
    stmt = astree.mk_instr_sequence([assignment])

    print(astapi.stmtstr("strb_1: low-level", stmt))


def strb_2 () -> None:

    # 0x11dd0  LDR            R3, 0x11ea0              R3 := 0x2242bc
    # 0x11dd8  ADDS           R3, R3, PC               R3 := (R3 + PC) (= 0x236098)
    # 0x11e04  STRB           R12, [R3, #0x411]        gv_0x2364a9 := ( lsb R3_in)

    astapi = ASTreeSetup("strb_2")
    astree = astapi.astree
    
    gvtype = astree.unsigned_char_type
    gvinfo = astree.mk_vinfo("gv_0x2364a9", vtype=gvtype, globaladdress=int("0x2364a9", 16))
    gvlval = astree.mk_vinfo_lval(gvinfo)
    r12 = astree.mk_named_lval_expression("R12", vtype=astree.unsigned_char_type)

    assignment = astree.mk_assign(gvlval, r12)
    stmt = astree.mk_instr_sequence([assignment])

    print(astapi.stmtstr("strb_2: resolve indirect memory reference", stmt))


def strb_3 () -> None:

    # 0x11dd0  LDR            R3, 0x11ea0              R3 := 0x2242bc
    # 0x11dd8  ADDS           R3, R3, PC               R3 := (R3 + PC) (= 0x236098)
    # 0x11e04  STRB           R12, [R3, #0x411]        gv_0x2364a9 := ( lsb R3_in)
    #
    # with header/definition information:
    # struct can_frame {
    #   unsigned int can_id;
    #   unsigned char can_dlc;
    #   unsigned char __pad;
    #   unsigned char __res0;
    #   unsigned char __res1;
    #   unsigned char data[8];
    # };
    #
    # struct can_frame CTS;  # at address 0x4364a0

    astapi = ASTreeSetup("strb_3")
    astree = astapi.astree
    
    can_frame_compinfo_key = 14   # it is the user's responsibility to ensure this key is unique
    can_frame_compinfo = astree.mk_compinfo_with_fields(
        "can_frame",
        can_frame_compinfo_key,
        [("can_id", astree.int_type),
         ("can_dlc", astree.unsigned_char_type),
         ("__pad", astree.unsigned_char_type),
         ("__res0", astree.unsigned_char_type),
         ("__res1", astree.unsigned_char_type),
         ("data",
          astree.mk_array_type(astree.unsigned_char_type, size=astree.mk_integer_constant(8)))])
    can_frame_type = astree.mk_comp_type_by_key(can_frame_compinfo_key, "can_frame")

    cts_vinfo = astree.mk_vinfo("CTS", vtype=can_frame_type, globaladdress=int("0x2364a0", 16))
    cts_data_offset = astree.mk_field_offset(
        "data",
        can_frame_compinfo_key,
        offset = astree.mk_scalar_index_offset(1))

    lval = astree.mk_vinfo_lval(cts_vinfo, offset=cts_data_offset)
    r12 = astree.mk_named_lval_expression("R12", vtype=astree.unsigned_char_type)    

    assignment1 = astree.mk_assign(lval, r12)

    stmt = astree.mk_instr_sequence([assignment1])

    print(astapi.stmtstr(
        "strb_3: locate left-hand-side within defined global struct CTS",
        stmt))


def strb_4 () -> None:

    # 0x11ca2  STMDB          R4, {R0,R1,R2,R3}
    # 0x11dd0  LDR            R3, 0x11ea0              R3 := 0x2242bc
    # 0x11dd8  ADDS           R3, R3, PC               R3 := (R3 + PC) (= 0x236098)
    # 0x11df0  LDRB.W         R12, [SP, #0xc]          R12 := R3_in    
    # 0x11e04  STRB           R12, [R3, #0x411]        gv_0x2364a9 := ( lsb R3_in)
    #
    # with header/definition information:
    # struct can_frame {
    #   unsigned int can_id;
    #   unsigned char can_dlc;
    #   unsigned char __pad;
    #   unsigned char __res0;
    #   unsigned char __res1;
    #   unsigned char data[8];
    # };
    #
    # struct can_frame CTS;  # at address 0x4364a0
    #
    # void handler(      # at address 0x11c9c
    #      struct can_frame frame,
    #      int desc,
    #      unsigned char sa);

    astapi = ASTreeSetup("strb_4")
    astree = astapi.astree
    
    can_frame_compinfo_key = 14   # it is the user's responsibility to ensure this key is unique
    can_frame_compinfo = astree.mk_compinfo_with_fields(
        "can_frame",
        can_frame_compinfo_key,
        [("can_id", astree.int_type),
         ("can_dlc", astree.unsigned_char_type),
         ("__pad", astree.unsigned_char_type),
         ("__res0", astree.unsigned_char_type),
         ("__res1", astree.unsigned_char_type),
         ("data",
          astree.mk_array_type(astree.unsigned_char_type, size=astree.mk_integer_constant(8)))])
    can_frame_type = astree.mk_comp_type_by_key(can_frame_compinfo_key, "can_frame")

    cts_vinfo = astree.mk_vinfo("CTS", vtype=can_frame_type, globaladdress=int("0x2364a0", 16))
    cts_data_offset = astree.mk_field_offset(
        "data",
        can_frame_compinfo_key,
        offset=astree.mk_scalar_index_offset(1))

    ftype = astree.mk_function_with_arguments_type(
        voidtype,
        [("frame", can_frame_type),
         ("desc", astree.int_type),
         ("sa", astree.unsigned_char_type)])
    fproto = astree.mk_vinfo("handler", vtype=ftype)
    astree.set_function_prototype(fproto)
    
    lval = astree.mk_vinfo_lval(cts_vinfo, offset=cts_data_offset)
    pframe = astree.mk_vinfo("frame", vtype=can_frame_type, parameter=0)
    pframe_offset = astree.mk_field_offset(
        "data",
        can_frame_compinfo_key,
        offset=astree.mk_scalar_index_offset(4))
    frame = astree.mk_named_lval_expression(
        "frame", vtype=can_frame_type, parameter=0, offset=pframe_offset)

    assignment1 = astree.mk_assign(lval, frame)

    stmt = astree.mk_instr_sequence([assignment1])

    print(astapi.stmtstr(
        "strb_4: locate left-hand-side within defined global struct CTS\n"
        + "and right-hand-side in function parameter\n",
        stmt))


if __name__ == "__main__":

    strb_low_level ()
    strb_2 ()
    strb_3 ()
    strb_4 ()

