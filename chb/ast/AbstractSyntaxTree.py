# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
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
"""Construction of abstract syntax tree."""

import json

from typing import (
    Any,
    Callable,
    cast,
    Dict,
    List,
    Mapping,
    NewType,
    Optional,
    Sequence,
    Tuple,
    TYPE_CHECKING,
    Union)

from chb.ast.ASTFormalVarInfo import ASTFormalVarInfo

import chb.ast.ASTNode as AST

from chb.ast.ASTSymbolTable import ASTSymbolTable, ASTLocalSymbolTable

import chb.ast.ASTUtil as AU
from chb.ast.ASTVarInfo import ASTVarInfo

if TYPE_CHECKING:
    from chb.bctypes.BCFieldInfo import BCFieldInfo
    from chb.bctypes.BCFunArgs import BCFunArg
    from chb.bctypes.BCFunctionDefinition import BCFunctionDefinition
    from chb.bctypes.BCTyp import BCTyp, BCTypFun, BCTypComp, BCTypArray, BCTypPtr
    from chb.bctypes.BCVarInfo import BCVarInfo


ASTSpanRecord = NewType(
    "ASTSpanRecord", Dict[str, Union[int, List[Dict[str, Union[str, int]]]]])

"""fname -> registers/stack -> name/offset -> [span/altname -> (low, high), name]."""
VariableNamesRec = NewType(
    "VariableNamesRec",
    Dict[str, Dict[str, Dict[str, List[Dict[str, Union[Tuple[str, str], str]]]]]])

nooffset = AST.ASTNoOffset()


'''
class VariableNames:

    def __init__(self, namerecords: VariableNamesRec) -> None:
        self._namerecords = namerecords

    @property
    def namerecords(self) -> VariableNamesRec:
        return self._namerecords

    def has_register_variable(self, fname: str, v: str) -> bool:
        return (
            fname in self.namerecords
            and "registers" in self.namerecords[fname]
            and v in self.namerecords[fname]["registers"])

    def has_stack_variable(self, fname: str, offset: int) -> bool:
        return (
            fname in self.namerecords
            and "stack" in self.namerecords[fname]
            and str(offset) in self.namerecords[fname]["stack"])

    def has_other_variable(self, fname: str, name: str) -> bool:
        return (
            fname in self.namerecords
            and "other" in self.namerecords[fname]
            and name in self.namerecords[fname]["other"])

    def register_variable(self, fname: str, v: str, addr: str) -> Optional[str]:
        if self.has_register_variable(fname, v):
            vrec = self.namerecords[fname]["registers"][v]
            addri = int(addr, 16)
            for span in vrec:
                if "span" in span:
                    vlow = int(span["span"][0], 16)
                    vhigh = int(span["span"][1], 16)
                    if vlow <= addri and addri <= vhigh:
                        return cast(str, span["altname"])
                else:
                    # variable name applies throughout the function
                    return cast(str, span["altname"])
            else:
                return None
        else:
            return None

    def stack_variable(self, fname: str, offset: int, addr: str) -> Optional[str]:
        if self.has_stack_variable(fname, offset):
            vrec = self.namerecords[fname]["stack"][str(offset)]
            addri = int(addr, 16)
            for span in vrec:
                if "span" in span:
                    vlow = int(span["span"][0], 16)
                    vhigh = int(span["span"][1], 16)
                    if vlow <= addri and addri <= vhigh:
                        return cast(str, span["altname"])
                else:
                    # variable name applies throughout the function
                    return cast(str, span["altname"])
            else:
                return None
        else:
            return None

    def other_variable(self, fname: str, name: str) -> Optional[str]:
        if self.has_other_variable(fname, name):
            vrec = self.namerecords[fname]["other"][name]
            return cast(str, vrec[0]["altname"])
        else:
            return None
'''


class AbstractSyntaxTree:

    def __init__(
            self,
            faddr: str,
            fname: str,
            localsymboltable: ASTLocalSymbolTable) -> None:
        self._faddr = faddr
        self._fname = fname  # same as faddr if no name provided
        self._counter = 0
        self._tmpcounter = 0
        self._spans: List[ASTSpanRecord] = []
        self._symboltable = localsymboltable
        self._unsupported: Dict[str, List[str]] = {}
        self._notes: List[str] = []

    def add_note(self, note: str) -> None:
        self._notes.append(note)

    @property
    def notes(self) -> List[str]:
        return self._notes

    @property
    def fname(self) -> str:
        return self._fname

    @property
    def symboltable(self) -> ASTLocalSymbolTable:
        return self._symboltable

    @property
    def spans(self) -> List[ASTSpanRecord]:
        return self._spans

    def diagnostics(self) -> List[str]:
        return self.notes + self.symboltable.diagnostics

    def storage_records(self) -> List[Dict[str, str]]:
        return AU.storage_records(list(self.symboltable.symbols()))

    def global_symbols(self) -> Sequence[AST.ASTVarInfo]:
        return self.symboltable.global_symbols()

    def set_functiondef(self, d: "BCFunctionDefinition") -> None:
        self._functiondef = d

    def set_function_prototype(self, p: "BCVarInfo") -> None:
        self._fprotoype = p
        self.symboltable.set_function_prototype(p)

    def has_functiondef(self) -> bool:
        return self._functiondef is not None

    @property
    def functiondef(self) -> "BCFunctionDefinition":
        if self._functiondef:
            return self._functiondef
        else:
            raise Exception("Function has no functiondef")

    def get_formal_locindices(
            self, argindex: int) -> Tuple[ASTFormalVarInfo, List[int]]:
        return self.symboltable.get_formal_locindices(argindex)

    def function_argument(self, index: int) -> List[AST.ASTLval]:
        """Return the argument(s) with the given index (zero-based).

        There may be more than one argument, in case of a packed array.
        """
        return self.symboltable.function_argument(index)

    def has_symbol(self, name: str) -> bool:
        return self.symboltable.has_symbol(name)

    def get_symbol(self, name: str) -> AST.ASTVarInfo:
        return self.symboltable.get_symbol(name)

    def add_symbol(
            self,
            name: str,
            vtype: Optional["BCTyp"] = None,
            size: Optional[int] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None) -> AST.ASTVarInfo:
        return self.symboltable.add_symbol(
            name,
            vtype=vtype,
            size=size,
            parameter=parameter,
            globaladdress=globaladdress)

    def new_id(self) -> int:
        """A single sequence of id's is used for statement and instruction id.

        That is, the set of instruction id's is disjoint from the set of stmt id's.
        """
        id = self._counter
        self._counter += 1
        return id

    def new_tmp_id(self) -> int:
        tmpid = self._tmpcounter
        self._tmpcounter += 1
        return tmpid

    def add_span(self, span: ASTSpanRecord) -> None:
        self._spans.append(span)

    def add_instruction_span(self, id: int, base: str, bytestring: str) -> None:
        span: Dict[str, Union[str, int]] = {}
        span["base_va"] = base
        span["size"] = len(bytestring) // 2
        spanrec: Dict[str, Any] = {}
        spanrec["id"] = id
        spanrec["spans"] = [span]
        self.add_span(cast(ASTSpanRecord, spanrec))

    def add_instruction_unsupported(self, mnem: str, instr: str) -> None:
        self._unsupported.setdefault(mnem, [])
        self._unsupported[mnem].append(instr)

    @property
    def unsupported_instructions(self) -> Dict[str, List[str]]:
        return self._unsupported

    def function_returntype(self, name: str) -> Optional["BCTyp"]:
        return self.symboltable.function_returntype(name)

    def is_variable_address(self, gaddr: int) -> Optional[str]:
        return self.symboltable.is_variable_address(gaddr)

    def is_struct_field_address(self, gaddr: int) -> bool:
        return self.symboltable.is_struct_field_address(gaddr)

    def get_struct_field_address(self, gaddr: int) -> AST.ASTExpr:
        return self.symboltable.get_struct_field_address(gaddr)

    # ------------------------------------------------------ make statements ---

    def mk_block(self, stmts: List[AST.ASTStmt]) -> AST.ASTBlock:
        stmtid = self.new_id()
        return AST.ASTBlock(stmtid, stmts)

    def mk_return_stmt(self, expr: Optional[AST.ASTExpr]) -> AST.ASTReturn:
        id = self.new_id()
        return AST.ASTReturn(id, expr)

    def mk_branch(
            self,
            condition: Optional[AST.ASTExpr],
            ifbranch: AST.ASTStmt,
            elsebranch: AST.ASTStmt,
            relative_offset: int) -> AST.ASTStmt:
        stmtid = self.new_id()
        if condition is None:
            # create a new unknown (unitialized) variable
            condvar = self.mk_temp_lval()
            condition = self.mk_lval_expr(condvar)
        return AST.ASTBranch(
            stmtid, condition, ifbranch, elsebranch, relative_offset)

    def mk_instr_sequence(
            self, instrs: List[AST.ASTInstruction]) -> AST.ASTInstrSequence:
        instrid = self.new_id()
        return AST.ASTInstrSequence(instrid, instrs)

    # ---------------------------------------------------- make instructions ---

    def mk_assign(
            self,
            lval: AST.ASTLval,
            rhs: AST.ASTExpr,
            annotations: List[str] = []) -> AST.ASTAssign:
        instrid = self.new_id()
        return AST.ASTAssign(instrid, lval, rhs, annotations=annotations)

    def mk_call(
            self,
            lval: AST.ASTLval,
            tgt: AST.ASTExpr,
            args: List[AST.ASTExpr]) -> AST.ASTCall:
        instrid = self.new_id()
        return AST.ASTCall(instrid, lval, tgt, args)    

    # ----------------------------------------------------- make lvals/exprs ---

    def mk_vinfo_variable(self, varinfo: ASTVarInfo) -> AST.ASTVariable:
        return AST.ASTVariable(varinfo)

    def mk_variable(self, name: str) -> AST.ASTVariable:
        if self.has_symbol(name):
            varinfo = self.get_symbol(name)
        else:
            varinfo = self.add_symbol(name)
        return self.mk_vinfo_variable(varinfo)

    def mk_lval(
            self,
            lhost: AST.ASTLHost,
            offset: AST.ASTOffset) -> AST.ASTLval:
        return AST.ASTLval(lhost, offset)

    def mk_lval_expr(self, lval: AST.ASTLval) -> AST.ASTExpr:
        return AST.ASTLvalExpr(lval)

    def mk_vinfo_variable_lval(self, varinfo: ASTVarInfo) -> AST.ASTLval:
        var = self.mk_vinfo_variable(varinfo)
        return AST.ASTLval(var, nooffset)

    def mk_variable_lval(self, name: str) -> AST.ASTLval:
        var = self.mk_variable(name)
        return AST.ASTLval(var, nooffset)    

    def mk_named_lval(self, name: str) -> AST.ASTLval:
        var = self.mk_variable(name)
        return AST.ASTLval(var, nooffset)

    def mk_ignored_lval(self) -> AST.ASTLval:
        return self.mk_named_lval("ignored_xxx")

    def mk_global_variable(
            self,
            name: str,
            vtype: Optional["BCTyp"] = None,
            globaladdress: Optional[int] = None) -> AST.ASTVariable:
        varinfo = self.add_symbol(name, vtype=vtype, globaladdress=globaladdress)
        return AST.ASTVariable(varinfo)

    def mk_global_variable_lval(
            self,
            name: str,
            vtype: Optional["BCTyp"] = None,
            globaladdress: Optional[int] = None) -> AST.ASTLval:
        var = self.mk_global_variable(
            name, vtype=vtype, globaladdress=globaladdress)
        return AST.ASTLval(var, nooffset)

    def mk_global_variable_expr(
            self,
            name: str,
            vtype: Optional["BCTyp"] = None,
            globaladdress: Optional[int] = None) -> AST.ASTExpr:
        lval = self.mk_global_variable_lval(
            name, vtype=vtype, globaladdress=globaladdress)
        return AST.ASTLvalExpr(lval)

    def mk_returnval_variable(
            self,
            iaddr: str,
            vtype: Optional["BCTyp"]) -> AST.ASTVariable:
        name = "rtn_" + iaddr
        varinfo = self.add_symbol(name, vtype=vtype, size=4)
        return AST.ASTVariable(varinfo)

    def mk_returnval_variable_lval(
            self,
            iaddr: str,
            vtype: Optional["BCTyp"]) -> AST.ASTLval:
        var = self.mk_returnval_variable(iaddr, vtype)
        return AST.ASTLval(var, nooffset)    

    def mk_register_variable(
            self,
            name: str,
            vtype: Optional["BCTyp"] = None,
            parameter: Optional[int] = None) -> AST.ASTVariable:
        varinfo = self.add_symbol(name, vtype=vtype, parameter=parameter)
        return AST.ASTVariable(varinfo)

    def mk_register_variable_lval(
            self,
            name: str,
            vtype: Optional["BCTyp"] = None,
            parameter: Optional[int] = None) -> AST.ASTLval:
        var = self.mk_register_variable(name, vtype, parameter)
        return AST.ASTLval(var, nooffset)

    def mk_register_variable_expr(
            self, name: str,
            vtype: Optional["BCTyp"] = None,
            parameter: Optional[int] = None) -> AST.ASTExpr:
        lval = self.mk_register_variable_lval(name, vtype, parameter)
        return AST.ASTLvalExpr(lval)    

    def mk_stack_variable(
            self,
            offset: int,
            name: Optional[str] = None,
            vtype: Optional["BCTyp"] = None,
            parameter: Optional[int] = None) -> AST.ASTVariable:
        if name is None:
            if offset < 0:
                name = "localvar_" + str(-offset)
            elif offset == 0:
                name = "localvar_0"
            else:
                name = "argvar_" + str(offset)
        varinfo = self.add_symbol(name, vtype=vtype, parameter=parameter)
        return AST.ASTVariable(varinfo)

    def mk_stack_variable_lval(
            self,
            offset: int,
            name: Optional[str] = None,
            vtype: Optional["BCTyp"] = None,
            parameter: Optional[int] = None) -> AST.ASTLval:
        var = self.mk_stack_variable(offset, name, vtype, parameter)
        return AST.ASTLval(var, nooffset)    

    def mk_temp_lval(self) -> AST.ASTLval:
        tmpname = "temp" + str(self.new_tmp_id())
        return self.mk_named_lval(tmpname)

    def mk_formal_lval(self, formal: ASTFormalVarInfo) -> AST.ASTLval:
        var = AST.ASTVariable(formal)
        return AST.ASTLval(var, nooffset)

    def mk_memref(self, memexp: AST.ASTExpr) -> AST.ASTMemRef:
        return AST.ASTMemRef(memexp)

    def mk_memref_lval(
            self,
            memexp: AST.ASTExpr,
            offset: AST.ASTOffset = nooffset) -> AST.ASTLval:
        memref = self.mk_memref(memexp)
        return AST.ASTLval(memref, offset)

    def mk_memref_expr(
            self,
            memexp: AST.ASTExpr,
            offset: AST.ASTOffset = nooffset) -> AST.ASTExpr:
        memreflval = self.mk_memref_lval(memexp, offset)
        return AST.ASTLvalExpr(memreflval)

    def mk_scalar_index_offset(
            self,
            index: int,
            offset: AST.ASTOffset = nooffset) -> AST.ASTIndexOffset:
        indexexpr = self.mk_integer_constant(index)
        return AST.ASTIndexOffset(indexexpr, offset)

    def mk_expr_index_offset(
            self,
            indexexpr: AST.ASTExpr,
            offset: AST.ASTOffset = nooffset) -> AST.ASTIndexOffset:
        return AST.ASTIndexOffset(indexexpr, offset)

    def mk_field_offset(
            self,
            fieldname: str,
            fieldtype: "BCTyp",
            offset: AST.ASTOffset = nooffset) -> AST.ASTFieldOffset:
        return AST.ASTFieldOffset(fieldname, fieldtype, offset)

    def mk_integer_constant(self, cvalue: int) -> AST.ASTIntegerConstant:
        gvinfo = AU.has_global_denotation(self.global_symbols(), hex(cvalue))
        return AST.ASTIntegerConstant(cvalue)

    def mk_string_constant(
            self, expr: AST.ASTExpr, cstr: str, saddr: str) -> AST.ASTStringConstant:
        return AST.ASTStringConstant(expr, cstr, saddr)

    def mk_address_of(self, lval: AST.ASTLval) -> AST.ASTAddressOf:
        return AST.ASTAddressOf(lval)

    def mk_byte_expr(self, index: int, x: AST.ASTExpr) -> AST.ASTExpr:
        if index == 0:
            mask = self.mk_integer_constant(255)
            return self.mk_binary_op("band", x, mask)
        elif index == 1:
            mask = self.mk_integer_constant(255)
            shift = self.mk_integer_constant(8)
            shiftop = self.mk_binary_op("lsr", x, shift)
            return self.mk_binary_op("band", x, mask)
        elif index == 2:
            mask = self.mk_integer_constant(255)
            shift = self.mk_integer_constant(16)
            shiftop = self.mk_binary_op("lsr", x, shift)
            return self.mk_binary_op("band", x, mask)
        elif index == 3:
            shift = self.mk_integer_constant(24)
            return self.mk_binary_op("lsr", x, shift)
        else:
            raise Exception("Byte extraction limited to 32 bit operands")

    def mk_byte_sum(self, bytes: List[AST.ASTExpr]) -> AST.ASTExpr:
        """Return expression for the sum of the bytes, least significant first."""

        result: AST.ASTExpr = self.mk_integer_constant(0)
        shift = 0
        for b in bytes:
            addend = self.mk_binary_op(
                "shiftlt", b, self.mk_integer_constant(shift))
            result = self.mk_binary_op("plus", result, addend)
            shift += 8
        return result

    def mk_binary_op(
            self, op: str,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr) -> AST.ASTExpr:
        if exp2.is_integer_constant and op in ["lsl", "shiftlt"]:
            expvalue = cast(AST.ASTIntegerConstant, exp2).cvalue
            if expvalue == 0:
                return exp1

        if exp1.is_integer_constant and op in ["plus"]:
            expvalue = cast(AST.ASTIntegerConstant, exp1).cvalue
            if expvalue == 0:
                return exp2

        if exp1.is_integer_constant and exp2.is_integer_constant and op == "band":
            exp1value = cast(AST.ASTIntegerConstant, exp1).cvalue
            exp2value = cast(AST.ASTIntegerConstant, exp2).cvalue

            # 0 & x = x & 0 = 0
            if exp1value == 0:
                return exp1
            elif exp2value == 0:
                return exp2

            # x & 255 = x  if x <= 255
            if exp1value <= 255 and exp2value == 255:
                return exp1

        if exp1.is_ast_lval_expr and exp2.is_integer_constant and op == "band":
            exp1lval = cast(AST.ASTLvalExpr, exp1).lval
            if exp1lval.ctype:
                exp2value = cast(AST.ASTIntegerConstant, exp2).cvalue
                typesize = exp1lval.ctype.byte_size()

                # if the type is smaller than the mask, ignore the mask
                if exp2value in [255, (256 * 256) - 1] and typesize == 1:
                    return exp1

        if exp1.is_ast_binary_op and exp2.is_integer_constant and op == "band":
            exp1 = cast(AST.ASTBinaryOp, exp1)
            exp2value = cast(AST.ASTIntegerConstant, exp2).cvalue

            # (x & y) & z = x & y  if y <= z
            if exp1.exp2.is_integer_constant and exp1.op == "band":
                exp12value = cast(AST.ASTIntegerConstant, exp1.exp2).cvalue
                if exp12value <= exp2value:
                    return exp1

        if (
                exp1.is_ast_binary_op
                and exp2.is_integer_constant
                and op == "eq"):
            exp1 = cast(AST.ASTBinaryOp, exp1)
            exp2value = cast(AST.ASTIntegerConstant, exp2).cvalue

            # (x != y) == 0  ==> x == y
            if exp2value == 0 and exp1.op in ["ne", "neq"]:
                return self.mk_binary_op("eq", exp1.exp1, exp1.exp2)

        return AST.ASTBinaryOp(op, exp1, exp2)

    def mk_question(
            self,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr,
            exp3: AST.ASTExpr) -> AST.ASTExpr:
        return AST.ASTQuestion(exp1, exp2, exp3)

    def mk_unary_op(self, op: str, exp: AST.ASTExpr) -> AST.ASTExpr:
        if exp.is_ast_binary_op and op == "lnot":
            exp = cast(AST.ASTBinaryOp, exp)
            reversals: Dict[str, str] = {
                "ne": "eq",
                "eq": "ne",
                "gt": "le",
                "ge": "lt",
                "lt": "ge",
                "le": "gt"}
            if exp.op in reversals:
                newop = reversals[exp.op]
                return self.mk_binary_op(newop, exp.exp1, exp.exp2)
            if (
                    exp.op == "lor"
                    and exp.exp1.is_ast_binary_op
                    and exp.exp2.is_ast_binary_op):
                exp1 = cast(AST.ASTBinaryOp, exp.exp1)
                exp2 = cast(AST.ASTBinaryOp, exp.exp2)
                if exp1.op in reversals and exp2.op in reversals:
                    newop1 = reversals[exp1.op]
                    newop2 = reversals[exp2.op]
                    newexp1 = self.mk_binary_op(newop1, exp1.exp1, exp1.exp2)
                    newexp2 = self.mk_binary_op(newop2, exp2.exp1, exp2.exp2)
                    return self.mk_binary_op("land", newexp1, newexp2)

        return AST.ASTUnaryOp(op, exp)

    def mk_cast_expr(self, tgttyp: str, exp: AST.ASTExpr) -> AST.ASTExpr:
        return AST.ASTCastE(tgttyp, exp)

    # ---------------------------------------------------- AST rewriting ---

    def rewrite(self, node: AST.ASTNode) -> AST.ASTNode:
        if node.is_ast_stmt:
            return self.rewrite_stmt(cast(AST.ASTStmt, node))

        return node

    def rewrite_stmt(self, stmt: AST.ASTStmt) -> AST.ASTStmt:
        if stmt.is_ast_return:
            return self.rewrite_return(cast(AST.ASTReturn, stmt))
        if stmt.is_ast_block:
            return self.rewrite_block(cast(AST.ASTBlock, stmt))
        if stmt.is_ast_branch:
            return self.rewrite_branch(cast(AST.ASTBranch, stmt))
        if stmt.is_ast_instruction_sequence:
            return self.rewrite_instruction_sequence(
                cast(AST.ASTInstrSequence, stmt))

        return stmt

    def rewrite_return(self, retstmt: AST.ASTReturn) -> AST.ASTStmt:
        return retstmt

    def rewrite_block(self, block: AST.ASTBlock) -> AST.ASTStmt:
        return AST.ASTBlock(
            block.stmtid, [self.rewrite_stmt(s) for s in block.stmts])

    def rewrite_branch(self, branch: AST.ASTBranch) -> AST.ASTStmt:
        return AST.ASTBranch(
            branch.stmtid,
            self.rewrite_expr(branch.condition),
            self.rewrite_stmt(branch.ifstmt),
            self.rewrite_stmt(branch.elsestmt),
            branch.relative_offset)

    def rewrite_instruction_sequence(
            self, instrseq: AST.ASTInstrSequence) -> AST.ASTStmt:
        return AST.ASTInstrSequence(
            instrseq.stmtid,
            [self.rewrite_instruction(i) for i in instrseq.instructions])

    def rewrite_instruction(self, instr: AST.ASTInstruction) -> AST.ASTInstruction:
        if instr.is_ast_assign:
            return self.rewrite_assign(cast(AST.ASTAssign, instr))
        if instr.is_ast_call:
            return self.rewrite_call(cast(AST.ASTCall, instr))

        return instr

    def rewrite_assign(self, assign: AST.ASTAssign) -> AST.ASTInstruction:
        return AST.ASTAssign(
            assign.instrid,
            self.rewrite_lval(assign.lhs),
            self.rewrite_expr(assign.rhs),
            annotations=assign.annotations)

    def rewrite_call(self, call: AST.ASTCall) -> AST.ASTInstruction:
        return call

    '''
    def rewrite_array_lval_to_indexed_array_lval(
            self,
            memexp: AST.ASTBinaryOp,
            default: Callable[[], AST.ASTLval]) -> AST.ASTLval:
        base = cast(AST.ASTLvalExpr, memexp.exp1)
        if base.is_ast_substituted_expr:
            base = cast(AST.ASTSubstitutedExpr, base)
            basexpr = base.substituted_expr
            if basexpr.is_ast_lval_expr:
                base = cast(AST.ASTLvalExpr, basexpr)
        basetype = base.ctype
        if basetype and basetype.is_array:
            basetype = cast("BCTypArray", basetype)
            elsize = basetype.tgttyp.byte_size()
            if elsize == 1:
                indexexp = memexp.exp2
                indexoffset = self.mk_expr_index_offset(indexexp)
                return AST.ASTLval(base.lval.lhost, indexoffset)
            else:
                self.add_note("rewrite-array-to-array: 1")
                return default()
        else:
            self.add_note(
                "rewrite-array-to-array: 2"
                + "; base: "
                + str(base)
                + ": "
                + str(basetype))
            return default()

    def rewrite_base_lval_to_indexed_array_lval(
            self,
            memexp: AST.ASTBinaryOp,
            default: Callable[[], AST.ASTLval]) -> AST.ASTLval:
        base = cast(AST.ASTIntegerConstant, memexp.exp1)
        if base.macroname and (base.macroname, "__none__") in self.symboltable:
            basevar = self.symboltable[(base.macroname, "__none__")]
            basetype = basevar.vtype
            if basetype and basetype.is_array:
                basetype = cast("BCTypArray", basetype)
                elsize = basetype.tgttyp.byte_size()
                if memexp.exp2.is_ast_binary_op:
                    indexexp = cast(AST.ASTBinaryOp, memexp.exp2)
                    if indexexp.op in ["lsl", "shiftlt"]:
                        if indexexp.exp2.is_integer_constant:
                            shiftamount = cast(
                                AST.ASTIntegerConstant, indexexp.exp2)
                            if elsize == 4 and shiftamount.cvalue == 2:
                                newindexexp = self.mk_expr_index_offset(
                                    indexexp.exp1)
                                bvar = self.mk_variable(base.macroname)
                                lvalnewid = self.new_id()
                                return AST.ASTLval(lvalnewid, bvar, newindexexp)
                            else:
                                self.add_note("rewrite-to-array: 1")
                                return default()
                        else:
                            self.add_note("rewrite-to-array: 2")
                            return default()
                    else:
                        self.add_note("rewrite-to-array: 3")
                        return default()
                else:
                    self.add_note("rewrite-to-array: 4")
                    return default()
            else:
                self.add_note("rewrite-to-array: 5")
                return default()
        else:
            self.add_note("rewrite-to_array: 6")
            return default()


    def rewrite_lval_to_fieldoffset_lval(
            self,
            lvalid: int,
            memexp: AST.ASTBinaryOp,
            default: Callable[[], AST.ASTLval]) -> AST.ASTLval:
        intoffset = cast(AST.ASTIntegerConstant, memexp.exp2)
        base = cast(AST.ASTLvalExpr, memexp.exp1)
        if base.is_ast_substituted_expr:
            base = cast(AST.ASTSubstitutedExpr, base)
            basexpr = base.substituted_expr
            if basexpr.is_ast_lval_expr:
                base = cast(AST.ASTLvalExpr, basexpr)
        if base.lval.offset.is_index_offset:
            if base.lval.lhost.ctype and base.lval.lhost.ctype.is_array:
                basetype = cast("BCTypArray", base.lval.lhost.ctype)
                if basetype.tgttyp.is_pointer:
                    basetgttype = cast("BCTypPtr", basetype.tgttyp)
                    if basetgttype.tgttyp.is_struct:
                        structtyp = cast("BCTypComp", basetgttype.tgttyp)
                        compinfo = structtyp.compinfo
                        finfo = compinfo.field_at_offset(intoffset.cvalue)[0]
                        fieldoffset = self.mk_field_offset(
                            finfo.fieldname, finfo.fieldtype, AST.ASTNoOffset(-1))
                        newhostid = self.new_id()
                        newmemref = AST.ASTMemRef(newhostid, memexp.exp1)
                        newlvalid = self.new_id()
                        newlval = AST.ASTLval(
                            newlvalid, newmemref, fieldoffset)
                        return newlval
                    else:
                        self.add_note("rewrite-to-fieldoffset-1")
                        return default()
                else:
                    self.add_note("rewrite-to-fieldoffset-2")
                    return default()
            else:
                self.add_note("rewrite-to-fieldoffset-3")
                return default()
        else:
            self.add_note("rewrite-to_fieldoffset-4")
            return default()
    '''

    def rewrite_lval(self, lval: AST.ASTLval) -> AST.ASTLval:

        def default() -> AST.ASTLval:
            return AST.ASTLval(
                self.rewrite_lhost(lval.lhost),
                self.rewrite_offset(lval.offset))

        lhost = self.rewrite_lhost(lval.lhost)
        offset = self.rewrite_offset(lval.offset)
        if lhost.is_memref and offset.is_no_offset:
            lhost = cast(AST.ASTMemRef, lhost)
            if lhost.memexp.is_ast_binary_op:
                memexp = cast(AST.ASTBinaryOp, lhost.memexp)
                if memexp.op == "plus" and memexp.exp1.is_integer_constant:
                    # return self.rewrite_base_lval_to_indexed_array_lval(
                    #    lval.id, memexp, default)
                    self.add_note("rewrite_base_lval_to_indexed_array_lval")
                    return default()

                elif (
                        memexp.op == "plus"
                        and memexp.exp1.is_ast_lval_expr
                        and memexp.exp2.is_integer_constant):
                    # return self.rewrite_lval_to_fieldoffset_lval(
                    #    lval.id, memexp, default)
                    self.add_note("rewrite_lval_to_fieldoffset_lval")
                    return default()

                elif (
                        memexp.op == "plus"
                        and memexp.exp1.is_ast_lval_expr
                        and memexp.exp1.is_ast_substituted_expr):
                    # return self.rewrite_array_lval_to_indexed_array_lval(
                    #    lval.id, memexp, default)
                    self.add_note("rewrite_array_lval_to_indexed_array_lval")
                    return default()

                else:
                    self.add_note(
                        "rewrite-lval-1 memxp: "
                        + str(memexp.exp1)
                        + " "
                        + str(memexp.op)
                        + " "
                        + str(memexp.exp2)
                        + ": "
                        + str(memexp.exp1.ctype)
                        + "  "
                        + str(offset))
                    return default()
            else:
                self.add_note("rewrite-lval-2 lhost: " + str(lhost)) 
                return default()
        else:
            if offset.is_no_offset and (not lhost.ctype):
                return default()
            elif lval.ctype and lval.ctype.is_integer:
                return default()
            else:
                self.add_note(
                    "rewrite-lval-3: lhost: "
                    + str(lval)
                    + ": "
                    + str(lval.ctype))
                return default()

        return AST.ASTLval(
            lval.id,
            self.rewrite_lhost(lval.lhost),
            self.rewrite_offset(lval.offset))

    def rewrite_lhost(self, lhost: AST.ASTLHost) -> AST.ASTLHost:
        if lhost.is_variable:
            return lhost
        if lhost.is_memref:
            return self.rewrite_memref(cast(AST.ASTMemRef, lhost))

        return lhost

    def rewrite_memref(self, memref: AST.ASTMemRef) -> AST.ASTLHost:
        return AST.ASTMemRef(self.rewrite_expr(memref.memexp))

    def rewrite_offset(self, offset: AST.ASTOffset) -> AST.ASTOffset:
        if offset.is_no_offset:
            return offset
        if offset.is_field_offset:
            return offset
        if offset.is_index_offset:
            return offset

        return offset

    def rewrite_expr(self, expr: AST.ASTExpr) -> AST.ASTExpr:
        if expr.is_ast_constant:
            return self.rewrite_constant(cast(AST.ASTConstant, expr))
        if expr.is_ast_substituted_expr:
            return self.rewrite_substituted_expr(cast(AST.ASTSubstitutedExpr, expr))
        if expr.is_ast_lval_expr:
            return self.rewrite_lval_expr(cast(AST.ASTLvalExpr, expr))
        if expr.is_ast_cast_expr:
            return self.rewrite_cast_expr(cast(AST.ASTCastE, expr))
        if expr.is_ast_unary_op:
            return self.rewrite_unary_op(cast(AST.ASTUnaryOp, expr))
        if expr.is_ast_binary_op:
            return self.rewrite_binary_op(cast(AST.ASTBinaryOp, expr))
        if expr.is_ast_question:
            return self.rewrite_question(cast(AST.ASTQuestion, expr))

        return expr

    def rewrite_constant(self, expr: AST.ASTConstant) -> AST.ASTExpr:
        return expr

    def rewrite_substituted_expr(self, expr: AST.ASTSubstitutedExpr) -> AST.ASTExpr:
        return AST.ASTSubstitutedExpr(
            self.rewrite_lval(expr.lval),
            expr.assign_id,
            self.rewrite_expr(expr.substituted_expr))

    def rewrite_lval_expr(self, expr: AST.ASTLvalExpr) -> AST.ASTExpr:
        return AST.ASTLvalExpr(self.rewrite_lval(expr.lval))

    def rewrite_cast_expr(self, expr: AST.ASTCastE) -> AST.ASTExpr:
        return expr

    def rewrite_unary_op(self, expr: AST.ASTUnaryOp) -> AST.ASTExpr:
        return AST.ASTUnaryOp(expr.op, self.rewrite_expr(expr.exp1))

    def rewrite_binary_op(self, expr: AST.ASTBinaryOp) -> AST.ASTExpr:
        return AST.ASTBinaryOp(
            expr.op,
            self.rewrite_expr(expr.exp1),
            self.rewrite_expr(expr.exp2))

    def rewrite_question(self, expr: AST.ASTQuestion) -> AST.ASTExpr:
        return expr

    def __str__(self) -> str:
        lines: List[str] = []
        for r in self._spans:
            lines.append(str(r))
        return "\n".join(lines)
