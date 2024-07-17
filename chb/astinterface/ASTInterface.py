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
"""Construction of abstract syntax tree for an individual function."""

import json
import logging

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


from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree, ASTSpanRecord, nooffset
from chb.ast.ASTBasicCTyper import ASTBasicCTyper
from chb.ast.ASTByteSizeCalculator import (
    ASTByteSizeCalculator, ASTByteSizeCalculationException)
from chb.ast.ASTCTyper import ASTCTyper
import chb.ast.ASTNode as AST
from chb.ast.ASTProvenance import ASTProvenance
from chb.ast.ASTSerializer import ASTSerializer
from chb.ast.ASTStorage import ASTStorage
from chb.ast.ASTSymbolTable import (
    ASTSymbolTable, ASTLocalSymbolTable, ASTGlobalSymbolTable)

from chb.astinterface.ASTIFormalVarInfo import ASTIFormalVarInfo

from chb.astinterface.ASTIProvenance import ASTIProvenance
import chb.astinterface.ASTIUtil as AU

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.api.AppFunctionSignature import AppFunctionSignature
    from chb.astinterface.BC2ASTConverter import BC2ASTConverter
    from chb.bctypes.BCConverter import BCConverter
    from chb.bctypes.BCFieldInfo import BCFieldInfo
    from chb.bctypes.BCFunArgs import BCFunArg
    from chb.bctypes.BCFunctionDefinition import BCFunctionDefinition
    from chb.bctypes.BCTyp import BCTyp, BCTypFun, BCTypComp, BCTypArray, BCTypPtr
    from chb.bctypes.BCVarInfo import BCVarInfo
    from chb.invariants.VarInvariantFact import (
        DefUse,
        DefUseHigh,
        FlagReachingDefFact,
        ReachingDefFact,
        VarInvariantFact
    )


class ASTInterface:

    def __init__(
            self,
            astree: AbstractSyntaxTree,
            typconverter: "BC2ASTConverter",
            parameter_abi: str,
            srcprototype: Optional["BCVarInfo"] = None,
            astprototype: Optional[AST.ASTVarInfo] = None,
            appsignature: Optional["AppFunctionSignature"] = None,
            rdeflocs: Dict[str, List[List[str]]] = {},
            varintros: Dict[str, str] = {},
            stackvarintros: Dict[int, str] = {},
            verbose: bool = False) -> None:
        self._astree = astree
        self._srcprototype = srcprototype
        self._astprototype = astprototype
        self._appsignature = appsignature
        self._rdeflocs = rdeflocs
        self._varintros = varintros
        self._stackvarintros = stackvarintros
        self._typconverter = typconverter
        self._verbose = verbose
        self._ctyper = ASTBasicCTyper(astree.globalsymboltable)
        self._bytesizecalculator = ASTByteSizeCalculator(
            self._ctyper,
            structsizes=self._typconverter.structsizes)
        self._parameter_abi = parameter_abi
        self._srcformals: List[ASTIFormalVarInfo] = []
        self._ssa_counter: int = 0
        self._ssa_intros: Dict[str, Dict[str, AST.ASTVarInfo]] = {}
        self._stack_variables: Dict[int, AST.ASTVarInfo] = {}
        self._unsupported: Dict[str, List[str]] = {}
        self._annotations: Dict[int, List[str]] = {}
        self._astiprovenance = ASTIProvenance()
        self._ignoredlhs = self.mk_variable_lval("ignored")
        self._regdefinitions: Dict[str, Dict[str, Tuple[int, AST.ASTExpr]]] = {}
        self._localvardefinitions: Dict[str, Dict[str, AST.ASTExpr]] = {}
        self._initialize_formals()
        if self._srcprototype is not None:
            astprototype = self._srcprototype.convert(self._typconverter)
            self.set_asm_function_prototype(astprototype)
        elif self._astprototype is not None:
            self.set_asm_function_prototype(self._astprototype)

    @property
    def astree(self) -> AbstractSyntaxTree:
        return self._astree

    @property
    def srcprototype(self) -> Optional["BCVarInfo"]:
        return self._srcprototype

    @property
    def appsignature(self) -> Optional["AppFunctionSignature"]:
        return self._appsignature

    @property
    def rdeflocs(self) -> Dict[str, List[List[str]]]:
        return self._rdeflocs

    @property
    def varintros(self) -> Dict[str, str]:
        return self._varintros

    @property
    def stackvarintros(self) -> Dict[int, str]:
        return self._stackvarintros

    @property
    def ignoredlhs(self) -> AST.ASTLval:
        return self._ignoredlhs

    @property
    def typconverter(self) -> "BC2ASTConverter":
        return self._typconverter

    @property
    def verbose(self) -> bool:
        return self._verbose

    @property
    def ctyper(self) -> ASTCTyper:
        return self._ctyper

    @property
    def bytesize_calculator(self) -> ASTByteSizeCalculator:
        return self._bytesizecalculator

    def set_asm_function_prototype(self, p: AST.ASTVarInfo) -> None:
        self.astree.set_function_prototype(p)

    @property
    def parameter_abi(self) -> str:
        return self._parameter_abi

    @property
    def srcformals(self) -> List[ASTIFormalVarInfo]:
        return self._srcformals

    @property
    def annotations(self) -> Dict[int, List[str]]:
        return self._annotations

    @property
    def astiprovenance(self) -> ASTIProvenance:
        return self._astiprovenance

    def set_ast_provenance(self) -> None:
        self.astiprovenance.set_ast_provenance(self.astree.provenance)

    @property
    def provenance(self) -> ASTProvenance:
        return self.astree.provenance

    @property
    def serializer(self) -> ASTSerializer:
        return self.astree.serializer

    @property
    def regdefinitions(self) -> Dict[str, Dict[str, Tuple[int, AST.ASTExpr]]]:
        return self._regdefinitions

    def regdefinition(
            self, iaddr: str, reg: str) -> Optional[Tuple[int, AST.ASTExpr]]:
        if iaddr in self.regdefinitions:
            if reg in self.regdefinitions[iaddr]:
                return self.regdefinitions[iaddr][reg]
        return None

    def add_reg_definition(
            self,
            iaddr: str,
            lval: AST.ASTLval,
            expr: AST.ASTExpr) -> None:
        self._regdefinitions.setdefault(iaddr, {})
        self._regdefinitions[iaddr][str(lval)] = (lval.lvalid, expr)

    def expr_has_registers(self, expr: AST.ASTExpr) -> bool:
        for r in ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"]:
            if r in str(expr):
                return True
        return False

    @property
    def localvardefinitions(self) -> Dict[str, Dict[str, AST.ASTExpr]]:
        return self._localvardefinitions

    def localvardefinition(
            self, iaddr: str, var: str) -> Optional[AST.ASTExpr]:
        if iaddr in self.localvardefinitions:
            if var in self.localvardefinitions[iaddr]:
                return self.localvardefinitions[iaddr][var]

        return None

    def add_local_vardefinition(
            self,
            iaddr: str,
            var: str,
            expr: AST.ASTExpr) -> None:
        self._localvardefinitions.setdefault(iaddr, {})
        self._localvardefinitions[iaddr][var] = expr

    def has_variable_intro(self, iaddr: str) -> bool:
        return iaddr in self.varintros

    def get_variable_intro(self, iaddr: str) -> str:
        if self.has_variable_intro(iaddr):
            return self.varintros[iaddr]
        else:
            raise UF.CHBError("No variable intro found for " + iaddr)

    def has_stack_variable_intro(self, offset: int) -> bool:
        return offset in self.stackvarintros

    def get_stack_variable_intro(self, offset: int) -> str:
        if self.has_stack_variable_intro(offset):
            return self.stackvarintros[offset]
        else:
            raise UF.CHBError("No stack-variable intro found for " + str(offset))

    def set_available_expressions(
            self, aexprs: Dict[str, Dict[str, Tuple[int, int, str]]]) -> None:
        self.astree.set_available_expressions(aexprs)

    def add_instr_mapping(
            self,
            hl_instr: AST.ASTInstruction,
            ll_instr: AST.ASTInstruction) -> None:
        self.astiprovenance.add_instr_mapping(hl_instr, ll_instr)

    def add_instr_address(
            self,
            instr: AST.ASTInstruction,
            addresses: List[str]) -> None:
        self.astiprovenance.add_instr_address(instr, addresses)

    def add_condition_address(
            self,
            expr: AST.ASTExpr,
            addresses: List[str]) -> None:
        self.astiprovenance.add_condition_address(expr, addresses)

    def add_expr_mapping(
            self,
            hl_expr: AST.ASTExpr,
            ll_expr: AST.ASTExpr) -> None:
        self.astiprovenance.add_expr_mapping(hl_expr, ll_expr)

    def add_lval_mapping(
            self,
            hl_lval: AST.ASTLval,
            ll_lval: AST.ASTLval) -> None:
        self.astiprovenance.add_lval_mapping(hl_lval, ll_lval)

    def add_expr_reachingdefs(
            self,
            expr: AST.ASTExpr,
            reachingdefs: List[Optional["ReachingDefFact"]]) -> None:
        rdefs: List["ReachingDefFact"] = []
        for f in reachingdefs:
            if f is not None:
                rdefs.append(f)
        self.astiprovenance.add_expr_reachingdefs(expr, rdefs)

    def add_flag_expr_reachingdefs(
            self,
            expr: AST.ASTExpr,
            reachingdefs: List[Optional["FlagReachingDefFact"]]) -> None:
        rdefs: List["FlagReachingDefFact"] = []
        for f in reachingdefs:
            if f is not None:
                rdefs.append(f)
        self.astiprovenance.add_flag_expr_reachingdefs(expr, rdefs)

    def add_lval_defuses(
            self,
            lval: AST.ASTLval,
            uses: Optional["DefUse"]) -> None:
        self.astiprovenance.add_lval_defuses(lval, uses)

    def add_lval_defuses_high(
            self,
            lval: AST.ASTLval,
            uses: Optional["DefUseHigh"]) -> None:
        self.astiprovenance.add_lval_defuses_high(lval, uses)

    def add_lval_store(self, lval: AST.ASTLval) -> None:
        self.astiprovenance.add_lval_store(lval)

    def add_expose_instruction(self, instrid: int) -> None:
        self.astiprovenance.add_expose_instruction(instrid)

    @property
    def fname(self) -> str:
        return self.astree.fname

    @property
    def symboltable(self) -> ASTLocalSymbolTable:
        return self.astree.symboltable

    @property
    def globalsymboltable(self) -> ASTGlobalSymbolTable:
        return self.symboltable.globaltable

    def has_compinfo(self, ckey: int) -> bool:
        return self.globalsymboltable.has_compinfo(ckey)

    def compinfo(self, ckey: int) -> AST.ASTCompInfo:
        return self.globalsymboltable.compinfo(ckey)

    def type_size_in_bytes(self, typ: AST.ASTTyp) -> Optional[int]:
        try:
            return typ.index(self.bytesize_calculator)
        except ASTByteSizeCalculationException as e:
            chklogger.logger.warning(
                "Size of type cannot be calculated: %s (%s)",
                str(typ),
                str(e))
            return None

    def resolve_type(self, t: AST.ASTTyp) -> AST.ASTTyp:
        if t.is_typedef:
            t = cast(AST.ASTTypNamed, t)
            return self.globalsymboltable.resolve_typedef(t.typname)
        else:
            return t

    @property
    def spans(self) -> List[ASTSpanRecord]:
        return self.astree.spans

    def returns_void(self) -> bool:
        p = self.srcprototype
        if p is not None:
            ftype = cast("BCTypFun", p.vtype)
            return ftype.returntype.is_void
        else:
            return False

    def _initialize_formals(self) -> None:
        p = self.srcprototype
        if p is not None:
            ftype = cast("BCTypFun", p.vtype)
            if ftype.argtypes:
                nextindex = 0
                for (argindex, arg) in enumerate(ftype.argtypes.funargs):
                    nextindex = self.add_formal(
                        arg.name, arg.typ, argindex, nextindex)

            for bccompinfo in self.typconverter.compinfos_referenced.values():
                astcompinfo = bccompinfo.convert(self.typconverter)
                if self.symboltable.has_compinfo(astcompinfo.compkey):
                    symcompinfo = self.symboltable.compinfo(astcompinfo.compkey)
                    if astcompinfo.compname != symcompinfo.compname:
                        raise Exception(
                            "Encountered two different compinfos with the same key: "
                            + str(symcompinfo.compkey)
                            + ". Existing name: "
                            + symcompinfo.compname
                            + ", New name: "
                            + astcompinfo.compname)
                else:
                    self.symboltable.add_compinfo(astcompinfo)

        else:
            chklogger.logger.warning("No source prototype found")

    def global_symbols(self) -> Sequence[AST.ASTVarInfo]:
        return []
        # return self.symboltable.global_symbols()

    def get_formal_binary_argcount(self) -> int:
        """Return the total number of (binary) 4-byte argument slots."""

        return sum(f.numargs for f in self.srcformals)

    def get_formal_locindices(
            self, argindex: int) -> Tuple[ASTIFormalVarInfo, List[int]]:
        """Return the indices of the arg location(s) for argindex.

        There may be more than one location in case of a packed array.
        """

        for formal in reversed(self.srcformals):
            if argindex >= formal.argindex:
                if (argindex - formal.argindex) < formal.numargs:
                    return (formal, formal.arglocs_for_argindex(argindex))
                else:
                    raise UF.CHBError(
                        "get_formal_locindex: "
                        + str(argindex)
                        + " is too large. Formals:  "
                        + ", ".join(str(f) for f in self.srcformals))

        else:
            raise UF.CHBError("No formal found for argindex: " + str(argindex))

    def has_formal_locindices(self, argindex: int) -> bool:
        for formal in reversed(self.srcformals):
            if argindex >= formal.argindex:
                return ((argindex - formal.argindex) < formal.numargs)
        return False

    def function_argument(self, index: int) -> List[AST.ASTLval]:
        """Return the argument(s) with the given index (zero-based).

        There may be more than one argument, in case of a packed array.
        """

        if len(self.srcformals) > 0:
            if self.has_formal_locindices(index):
                (formal, locindices) = self.get_formal_locindices(index)
                regvar = AST.ASTVariable(formal.lifted_vinfo)
                lvals: List[AST.ASTLval] = []
                for locindex in locindices:
                    (loc, offset, size) = formal.argloc(locindex)
                    lvals.append(self.mk_lval(regvar, offset))
                return lvals
            else:
                chklogger.logger.warning(
                    "Function prototype does not match code: "
                    + "argument index reference %s is not accomodated by the "
                    + "formal arguments found: %s",
                    str(index),
                    ", ".join(str(f) for f in self.srcformals))
                return []
        else:
            return []

    def add_return_sequence(
            self,
            hexstring: str,
            assembly: List[str],
            address: str) -> None:
        self.astree.add_return_sequence(hexstring, assembly, address)

    def has_symbol(self, name: str) -> bool:
        return self.symboltable.has_symbol(name)

    def get_symbol(self, name: str) -> AST.ASTVarInfo:
        return self.symboltable.get_symbol(name)

    def add_symbol(
            self,
            name: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None) -> AST.ASTVarInfo:
        return self.astree.add_symbol(
            name,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress)

    def add_formal(
            self,
            vname: str,
            vtype: "BCTyp",
            parameter: int,
            nextindex: int) -> int:
        """Returns the next starting index for the argument in the binary."""

        asttyp = vtype.convert(self.typconverter)
        vinfo = self.add_symbol(vname, vtype=asttyp, parameter=parameter)
        formal = ASTIFormalVarInfo(
            vname, parameter, nextindex, vinfo, bctyp=vtype)
        nextindex = formal.initialize(self.parameter_abi)
        self._srcformals.append(formal)
        return nextindex

    def add_span(self, span: ASTSpanRecord) -> None:
        self.astree.add_span

    def add_instruction_span(self, id: int, base: str, bytestring: str) -> None:
        self.astree.add_instruction_span(id, base, bytestring)

    def add_instruction_unsupported(self, mnem: str, instr: str) -> None:
        self._unsupported.setdefault(mnem, [])
        self._unsupported[mnem].append(instr)

    @property
    def unsupported_instructions(self) -> Dict[str, List[str]]:
        return self._unsupported

    def function_returntype(self, name: str) -> Optional["BCTyp"]:
        return None
        # return self.symboltable.function_returntype(name)

    def is_variable_address(self, gaddr: int) -> Optional[str]:
        return None
        # return self.symboltable.is_variable_address(gaddr)

    def is_struct_field_address(self, gaddr: int) -> bool:
        return False
        # return self.symboltable.is_struct_field_address(gaddr)

    def get_struct_field_address(self, gaddr: int) -> AST.ASTExpr:
        raise NotImplementedError("get_struct_field_address")
        # return self.symboltable.get_struct_field_address(gaddr)

    def mk_global_variable_expr(
            self,
            name: str,
            vtype: Optional[AST.ASTTyp] = None,
            globaladdress: int = 0) -> AST.ASTExpr:
        return self.astree.mk_named_lval_expression(
            name, vtype=vtype,globaladdress=globaladdress)

    # ------------------------------------------------------ make statements ---

    def mk_block(
            self,
            stmts: List[AST.ASTStmt],
            labels: List[AST.ASTStmtLabel] = [],
            optlocationid: Optional[int] = None) -> AST.ASTBlock:
        return self.astree.mk_block(
            stmts, labels=labels, optlocationid=optlocationid)

    def mk_loop(
            self,
            body: AST.ASTStmt,
            mergeaddr: Optional[str] = None,
            continueaddr: Optional[str] = None,
            optlocationid: Optional[int] = None) -> AST.ASTLoop:
        return self.astree.mk_loop(body, mergeaddr=mergeaddr,
                                   continueaddr=continueaddr,
                                   optlocationid=optlocationid)

    def mk_return_stmt(
            self,
            expr: Optional[AST.ASTExpr],
            iaddr: Optional[str] = None,
            bytestring: Optional[str] = None,
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTReturn:

        def add_span(stmt: AST.ASTReturn) -> None:
            if iaddr is not None and bytestring is not None:
                self.astree.add_instruction_span(stmt.locationid, iaddr, bytestring)

        if expr is not None and iaddr is not None and bytestring is not None:
            self.astree.add_expr_span(expr.exprid, iaddr, bytestring)
        if expr is not None and expr.is_integer_constant:
            expr = cast(AST.ASTIntegerConstant, expr)
            if expr.cvalue == 0:
                fproto = self.symboltable.function_prototype
                if fproto is not None:
                    ftype = fproto.vtype
                    if ftype is not None:
                        if ftype.is_function:
                            ftype = cast(AST.ASTTypFun, ftype)
                            returntyp = ftype.returntyp
                            if returntyp.is_pointer:
                                cexpr = self.mk_cast_expr(returntyp, expr)
                                rstmt = self.astree.mk_return_stmt(cexpr, labels=labels)
                                add_span(rstmt)
                                return rstmt

        rstmt = self.astree.mk_return_stmt(expr, labels=labels)
        add_span(rstmt)
        return rstmt

    def mk_break_stmt(self) -> AST.ASTBreak:
        return self.astree.mk_break_stmt()

    def mk_continue_stmt(self) -> AST.ASTContinue:
        return self.astree.mk_continue_stmt()

    def mk_branch(
            self,
            condition: Optional[AST.ASTExpr],
            ifbranch: AST.ASTStmt,
            elsebranch: AST.ASTStmt,
            targetaddr: str,
            mergeaddr: Optional[str] = None,
            optlocationid: Optional[int] = None) -> AST.ASTStmt:
        return self.astree.mk_branch(
            condition,
            ifbranch,
            elsebranch,
            targetaddr,
            mergeaddr=mergeaddr,
            optlocationid=optlocationid)

    def mk_instr_sequence(
            self,
            instrs: List[AST.ASTInstruction],
            labels: List[AST.ASTStmtLabel] = [],
            optlocationid: Optional[int] = None) -> AST.ASTInstrSequence:
        return self.astree.mk_instr_sequence(
            instrs, labels=labels, optlocationid=optlocationid)

    def mk_goto_stmt(
            self,
            name: str,
            destaddr: str,
            wrapgoto: bool = False,
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTStmt:
        if wrapgoto:
            gotostmt = self.astree.mk_goto_stmt(name, destaddr)
            return self.mk_block([gotostmt], labels=labels)
        else:
            return self.astree.mk_goto_stmt(name, destaddr, labels=labels)

    def mk_switch_stmt(
            self,
            switchexpr: Optional[AST.ASTExpr],
            cases: AST.ASTStmt,
            mergeaddr: Optional[str],
            optlocationid: Optional[int] = None,
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTSwitchStmt:
        return self.astree.mk_switch_stmt(
            switchexpr, cases, mergeaddr=mergeaddr,
            optlocationid=optlocationid, labels=labels)

    # ---------------------------------------------------- make labels ---------

    def mk_label(self, name: str) -> AST.ASTLabel:
        return self.astree.mk_label(name)

    def mk_case_label(self, expr: Optional[AST.ASTExpr]) -> AST.ASTCaseLabel:
        return self.astree.mk_case_label(expr)

    def mk_default_label(self) -> AST.ASTDefaultLabel:
        return self.astree.mk_default_label()

    # ---------------------------------------------------- make instructions ---

    def mk_assign(
            self,
            lval: AST.ASTLval,
            rhs: AST.ASTExpr,
            iaddr: Optional[str] = None,
            bytestring: Optional[str] = None,
            annotations: List[str] = []) -> AST.ASTAssign:
        assign = self.astree.mk_assign(lval, rhs)
        if iaddr is not None and bytestring is not None:
            self.add_instruction_span(assign.locationid, iaddr, bytestring)
        self._annotations[assign.instrid] = annotations
        return assign

    def mk_call(
            self,
            lval: Optional[AST.ASTLval],
            tgt: AST.ASTExpr,
            args: List[AST.ASTExpr],
            iaddr: Optional[str] = None,
            bytestring: Optional[str] = None,
            annotations: List[str] = []) -> AST.ASTCall:
        call = self.astree.mk_call(lval, tgt, args)
        if iaddr is not None and bytestring is not None:
            self.add_instruction_span(call.locationid, iaddr, bytestring)
        self._annotations[call.instrid] = annotations
        return call

    def mk_asm(
            self,
            vola: bool,
            templates: List[str],
            clobbers: List[str],
            iaddr: Optional[str] = None,
            bytestring: Optional[str] = None,
            annotations: List[str] = []) -> AST.ASTAsm:
        call = self.astree.mk_asm(vola, templates, clobbers)
        if iaddr is not None and bytestring is not None:
            self.add_instruction_span(call.locationid, iaddr, bytestring)
        self._annotations[call.instrid] = annotations
        return call

    def mk_nop_instruction(
            self,
            descr: str,
            iaddr: Optional[str] = None,
            bytestring: Optional[str] = None,
            annotations: List[str] = []) -> AST.ASTNOPInstruction:
        nopinstr = self.astree.mk_nop_instruction(descr)
        if iaddr is not None and bytestring is not None:
            self.add_instruction_span(nopinstr.locationid, iaddr, bytestring)
        self._annotations[nopinstr.instrid] = annotations
        return nopinstr

    # ----------------------------------------------------- make lvals/exprs ---

    def mk_vinfo(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> AST.ASTVarInfo:
        return self.astree.mk_vinfo(
            vname,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr)

    def mk_vinfo_variable(self, vinfo: AST.ASTVarInfo) -> AST.ASTVariable:
        return self.astree.mk_vinfo_variable(vinfo)

    def mk_vinfo_lval(
            self,
            vinfo: AST.ASTVarInfo,
            offset: AST.ASTOffset = nooffset,
            anonymous: bool = False) -> AST.ASTLval:
        optlvalid = -1 if anonymous else None
        return self.astree.mk_vinfo_lval(
            vinfo, offset=offset, optlvalid=optlvalid)

    def mk_vinfo_lval_expression(
            self,
            vinfo: AST.ASTVarInfo,
            offset: AST.ASTOffset = nooffset,
            anonymous: bool = False) -> AST.ASTLvalExpr:
        optexprid = -1 if anonymous else None
        return self.astree.mk_vinfo_lval_expression(
            vinfo, offset=offset, optexprid=optexprid)

    def mk_lval_expr(self, lval: AST.ASTLval, anonymous: bool = False) -> AST.ASTExpr:
        return self.mk_lval_expression(lval, anonymous=anonymous)

    def mk_variable_lval(
            self,
            name: str,
            storage: Optional[ASTStorage] = None,
            anonymous: bool = False) -> AST.ASTLval:
        return self.mk_named_lval(name, storage=storage, anonymous=anonymous)

    def mk_named_variable(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> AST.ASTVariable:
        return self.astree.mk_named_variable(
            vname,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr)

    def mk_named_lval(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None,
            offset: AST.ASTOffset = nooffset,
            storage: Optional[ASTStorage] = None,
            anonymous: bool = False) -> AST.ASTLval:
        optlvalid = -1 if anonymous else None
        return self.astree.mk_named_lval(
            vname,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr,
            storage=storage,
            optlvalid=optlvalid)

    def mk_named_lval_expression(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None,
            offset: AST.ASTOffset = nooffset,
            storage: Optional[ASTStorage] = None,
            anonymous: bool = False) -> AST.ASTLvalExpr:
        optexprid = -1 if anonymous else None
        return self.astree.mk_named_lval_expression(
            vname,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr,
            offset=offset,
            storage=storage,
            optexprid=optexprid)

    def mk_lval(
            self,
            lhost: AST.ASTLHost,
            offset: AST.ASTOffset,
            storage: Optional[ASTStorage] = None,
            anonymous: bool = False) -> AST.ASTLval:
        optlvalid = -1 if anonymous else None
        return self.astree.mk_lval(
            lhost, offset, storage=storage, optlvalid=optlvalid)

    def mk_lval_expression(
            self, lval: AST.ASTLval, anonymous: bool = False) -> AST.ASTExpr:
        optexprid = -1 if anonymous else None
        return self.astree.mk_lval_expression(lval, optexprid=optexprid)

    @property
    def ssa_intros(self) -> Dict[str, Dict[str, AST.ASTVarInfo]]:
        """Return iaddr -> register -> ssa variable."""

        return self._ssa_intros

    @property
    def stack_variables(self) -> Dict[int, AST.ASTVarInfo]:
        return self._stack_variables

    def introduce_ssa_variables(
            self,
            rdeflocs: Dict[str, List[List[str]]],
            ftypes: Dict[str, Dict[str, "BCTyp"]]) -> None:
        """Creates ssa variables based on reaching definition locations.

        Lists with multiple locations will give rise to a single variable
        being created for all of those locations, as these all reach a
        particular use of the variable.
        """

        for (reg, locs) in rdeflocs.items():
            for lst in locs:
                if len(lst) > 0:
                    loc1 = lst[0]
                    vtype = None
                    if loc1 in ftypes:
                        if reg in ftypes[loc1]:
                            vbctype = ftypes[loc1][reg]
                            vtype = vbctype.convert(self.typconverter)
                    vinfo = self.mk_ssa_register_varinfo(reg, loc1, vtype=vtype)
                    for loc in lst:
                        self._ssa_intros.setdefault(loc, {})
                        self._ssa_intros[loc][reg] = vinfo

    def introduce_stack_variables(
            self, stackvartypes: Dict[int, "BCTyp"]) -> None:
        """Creates stack variables/buffers for all stack offsets with types. """

        for (offset, bctype) in stackvartypes.items():
            vtype = bctype.convert(self.typconverter)
            self.mk_stackvarinfo(offset, vtype=vtype)

    def mk_ssa_register_varinfo(
            self,
            name: str,
            iaddr: str,
            vtype: Optional[AST.ASTTyp] = None) -> AST.ASTVarInfo:
        if iaddr in self.ssa_intros and name in self.ssa_intros[iaddr]:
            vinfo = self.ssa_intros[iaddr][name]
            if vtype is not None and vinfo.vtype is None:
                vinfo.vtype = vtype
            return vinfo

        # create a new ssa variable
        if iaddr in self.varintros:
            vname = self.varintros[iaddr]
        else:
            ssaid = self._ssa_counter
            self._ssa_counter += 1
            vname = "ssa_" + name + "_" + str(ssaid)
        varinfo = self.add_symbol(vname, vtype=vtype)
        self._ssa_intros.setdefault(iaddr, {})
        self._ssa_intros[iaddr][name] = varinfo
        return varinfo

    def mk_stackvarinfo(
            self, offset: int, vtype: Optional[AST.ASTTyp]) -> AST.ASTVarInfo:
        if offset in self.stack_variables:
            vinfo = self.stack_variables[offset]
            if vtype is not None and vinfo.vtype is None:
                vinfo.vtype = vtype
            return vinfo

        # create a new stack variable
        if offset in self.stackvarintros:
            vname = self.stackvarintros[offset]
        else:
            vname = "stack_" + str(offset)
        varinfo = self.add_symbol(vname, vtype=vtype)
        self._stack_variables[offset] = varinfo
        return varinfo

    def mk_ssa_register_variable(
            self,
            name: str,
            iaddr: str,
            vtype: Optional[AST.ASTTyp] = None) -> AST.ASTVariable:
        varinfo = self.mk_ssa_register_varinfo(name, iaddr, vtype=vtype)
        return AST.ASTVariable(varinfo)

    def mk_stack_variable(
            self,
            offset: int,
            vtype: Optional[AST.ASTTyp] = None) -> AST.ASTVariable:
        varinfo = self.mk_stackvarinfo(offset, vtype=vtype)
        return AST.ASTVariable(varinfo)

    def mk_ssa_register_variable_lval(
            self,
            name: str,
            iaddr: str,
            vtype: Optional[AST.ASTTyp] = None) -> AST.ASTLval:
        vinfo = self.mk_ssa_register_varinfo(name, iaddr, vtype=vtype)
        storage = self.astree.mk_register_storage(name)
        return self.astree.mk_vinfo_lval(vinfo, storage=storage)

    def mk_stack_variable_lval(
            self,
            offset: int,
            vtype: Optional[AST.ASTTyp] = None) -> AST.ASTLval:
        vinfo = self.mk_stackvarinfo(offset, vtype=vtype)
        storage = self.astree.mk_stack_storage(offset)
        return self.astree.mk_vinfo_lval(vinfo, storage=storage)

    def mk_register_variable(
            self,
            name: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None) -> AST.ASTVariable:
        varinfo = self.add_symbol(name, vtype=vtype, parameter=parameter)
        return AST.ASTVariable(varinfo)

    def mk_register_variable_lval(
            self,
            name: str,
            registername: Optional[str] = None,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            anonymous: bool = False) -> AST.ASTLval:
        var = self.mk_register_variable(name, vtype, parameter)
        optlvalid = -1 if anonymous else None
        return self.astree.mk_register_variable_lval(
            name,
            registername=registername,
            vtype=vtype,
            parameter=parameter,
            optlvalid=optlvalid)

    def mk_flag_variable_lval(
            self,
            name: str,
            flagname: Optional[str] = None,
            vdescr: Optional[str] = None,
            anonymous: bool = False) -> AST.ASTLval:
        optlvalid = -1 if anonymous else None
        return self.astree.mk_flag_variable_lval(
            name, flagname=flagname, vdescr=vdescr, optlvalid=optlvalid)

    def mk_flag_variable_lval_expression(
            self,
            name: str,
            flagname: Optional[str] = None,
            vdescr: Optional[str] = None,
            anonymous: bool = False) -> AST.ASTLvalExpr:
        optexprid = -1 if anonymous else None
        optlvalid = -1 if anonymous else None
        return self.astree.mk_flag_variable_lval_expression(
            name,
            flagname=flagname,
            vdescr=vdescr,
            optlvalid=optlvalid,
            optexprid=optexprid)

    def mk_register_variable_expr(
            self, name: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            anonymous: bool = False) -> AST.ASTExpr:
        lval = self.mk_register_variable_lval(
            name, vtype=vtype, parameter=parameter, anonymous=anonymous)
        return self.mk_lval_expression(lval, anonymous=anonymous)

    def mk_temp_lval(self) -> AST.ASTLval:
        return self.astree.mk_tmp_lval()

    def mk_formal_lval(self, formal: ASTIFormalVarInfo) -> AST.ASTLval:
        var = AST.ASTVariable(formal.lifted_vinfo)
        return self.mk_lval(var, nooffset)

    def mk_memref(self, memexp: AST.ASTExpr) -> AST.ASTMemRef:
        return AST.ASTMemRef(memexp)

    def mk_memref_lval(
            self,
            memexp: AST.ASTExpr,
            offset: AST.ASTOffset = nooffset,
            anonymous: bool = False) -> AST.ASTLval:
        memref = self.mk_memref(memexp)
        return self.mk_lval(memref, offset, anonymous=anonymous)

    def mk_memref_expr(
            self,
            memexp: AST.ASTExpr,
            offset: AST.ASTOffset = nooffset,
            anonymous: bool = False) -> AST.ASTExpr:
        memreflval = self.mk_memref_lval(memexp, offset, anonymous=anonymous)
        return self.mk_lval_expression(memreflval, anonymous=anonymous)

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
            compkey: int,
            offset: AST.ASTOffset = nooffset) -> AST.ASTFieldOffset:
        return self.astree.mk_field_offset(fieldname, compkey, offset=offset)

    def split_address_int_offset(
            self,
            address: AST.ASTExpr) -> Tuple[AST.ASTExpr, List[AST.ASTExpr]]:
        if address.is_ast_binary_op:
            address = cast(AST.ASTBinaryOp, address)
            op = address.op
            base = address.exp1
            off = address.exp2
            (x, y) = self.split_address_int_offset(base)
            if op == "minus":
                offset = self.mk_unary_op("neg", address.exp2)
            else:
                offset = address.exp2
            newlist = [offset] + y[:]
            return (x, newlist)
        else:
            return (address, [])

    def add_index_list_offset(
            self,
            baseoffset: AST.ASTOffset,
            indexlist: List[AST.ASTExpr]) -> AST.ASTOffset:
        if len(indexlist) == 0:
            indexoffset = self.mk_scalar_index_offset(0)
            return self.add_offset(baseoffset, indexoffset)
        elif len(indexlist) == 1:
            indexoffset = self.mk_expr_index_offset(indexlist[0])
            return self.add_offset(baseoffset, indexoffset)
        else:
            exp1 = indexlist[0]
            exp2 = indexlist[1]
            sumexp = self.mk_simplified_binary_op("plus", exp1, exp2)
            ilist = [sumexp] + indexlist[2:]
            return self.add_index_list_offset(baseoffset, ilist)

    def add_offset(
            self,
            baseoffset: AST.ASTOffset,
            suboffset: AST.ASTOffset) -> AST.ASTOffset:
        if baseoffset.is_no_offset:
            return suboffset
        elif baseoffset.is_field_offset:
            baseoffset = cast(AST.ASTFieldOffset, baseoffset)
            return self.mk_field_offset(
                baseoffset.fieldname,
                baseoffset.compkey,
                self.add_offset(baseoffset.offset, suboffset))
        else:
            baseoffset = cast(AST.ASTIndexOffset, baseoffset)
            return self.mk_expr_index_offset(
                baseoffset.index_expr,
                self.add_offset(baseoffset.offset, suboffset))

    def add_to_index_offset(
            self,
            baseoffset: AST.ASTOffset,
            increm: int) -> AST.ASTOffset:
        if baseoffset.is_no_offset:
            raise UF.CHBError("Cannot add increment to no-offset")
        elif baseoffset.is_field_offset:
            baseoffset = cast(AST.ASTFieldOffset, baseoffset)
            return self.mk_field_offset(
                baseoffset.fieldname,
                baseoffset.compkey,
                self.add_to_index_offset(baseoffset.offset, increm))
        else:
            baseoffset = cast(AST.ASTIndexOffset, baseoffset)
            if baseoffset.index_expr.is_integer_constant and baseoffset.offset.is_no_offset:
                baseindex = cast(AST.ASTIntegerConstant, baseoffset.index_expr)
                newindex = baseindex.cvalue + increm
                return self.mk_scalar_index_offset(newindex)
            else:
                raise UF.CHBError("add_to_index_offset: not yet supported")

    def mk_integer_constant(self, cvalue: int, ikind: str = "iint") -> AST.ASTIntegerConstant:
        return self.astree.mk_integer_constant(cvalue, ikind=ikind)

    def mk_float_constant(
            self, fvalue: float, fkind: str = "float") -> AST.ASTFloatingPointConstant:
        return self.astree.mk_float_constant(fvalue, fkind=fkind)

    def mk_global_address_constant(
            self,
            cvalue: int,
            addressexpr: AST.ASTExpr) -> AST.ASTGlobalAddressConstant:
        return self.astree.mk_global_address_constant(cvalue, addressexpr)

    def mk_string_constant(
            self,
            expr: AST.ASTExpr,
            cstr: str,
            saddr: str) -> AST.ASTStringConstant:
        return self.astree.mk_string_constant(expr, cstr, saddr)

    def mk_address_of(
            self, lval: AST.ASTLval, anonymous: bool = False) -> AST.ASTAddressOf:
        optexprid = -1 if anonymous else None
        return self.astree.mk_address_of_expression(lval, optexprid=optexprid)

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
                "lsl", b, self.mk_integer_constant(shift))
            result = self.mk_binary_op("plus", result, addend)
            shift += 8
        return result

    def mk_binary_expression(
            self,
            op: str,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr,
            anonymous: bool = False) -> AST.ASTExpr:
        optexprid = -1 if anonymous else None

        # Note: in some cases pointers may be shifted right immediately
        # followed by a shift left by the same amount for alignment
        # purposes. Apply cast here to avoid assertion error in
        # abstractsyntaxtree._cast_if_needed.
        if op in ["lsr", "asr"]:
            t1 = exp1.ctype(self.ctyper)
            if t1 is not None and not t1.is_integer:
                tgtt = self.astree.mk_integer_ikind_type("iuint")
                chklogger.logger.info(
                    "Cast added to %s: %s",
                    str(exp1),
                    str(t1))
                exp1 = self.astree.mk_cast_expression(tgtt, exp1)

        return self.astree.mk_binary_expression(
            op, exp1, exp2, optexprid=optexprid)

    def mk_binary_op(
            self,
            op: str,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_binary_expression(op, exp1, exp2)

    def mk_simplified_binary_op(
            self,
            op: str,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr) -> AST.ASTExpr:
        if exp1.is_integer_constant and exp2.is_integer_constant:
            if op == "plus":
                exp1 = cast(AST.ASTIntegerConstant, exp1)
                exp2 = cast(AST.ASTIntegerConstant, exp2)
                return self.mk_integer_constant(exp1.cvalue + exp2.cvalue)
            else:
                return self.mk_binary_op(op, exp1, exp2)
        elif exp1.is_integer_constant and exp2.is_ast_unary_op:
            exp2 = cast(AST.ASTUnaryOp, exp2)
            if exp2.op == "neg" and exp2.exp1.is_integer_constant:
                exp1 = cast(AST.ASTIntegerConstant, exp1)
                exp2 = cast(AST.ASTIntegerConstant, exp2.exp1)
                return self.mk_integer_constant(exp1.cvalue - exp2.cvalue)
            else:
                return self.mk_binary_op(op, exp1, exp2)
        else:
            return self.mk_binary_op(op, exp1, exp2)

    def mk_question(
            self,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr,
            exp3: AST.ASTExpr) -> AST.ASTExpr:
        return self.astree.mk_question_expression(exp1, exp2, exp3)

    def mk_unary_op(
            self, op: str,
            exp: AST.ASTExpr,
            anonymous: bool = False) -> AST.ASTExpr:
        optexprid = -1 if anonymous else None
        return self.astree.mk_unary_expression(op, exp, optexprid=optexprid)

    def mk_cast_expr(
            self,
            tgttyp: AST.ASTTyp,
            exp: AST.ASTExpr,
            anonymous: bool = False) -> AST.ASTExpr:
        optexprid = -1 if anonymous else None
        return self.astree.mk_cast_expression(tgttyp, exp, optexprid=optexprid)

    # ---------------------------------------------------- types -----------

    def mk_function_with_arguments_type(
            self,
            returntype: AST.ASTTyp,
            arguments: List[Tuple[str, AST.ASTTyp]],
            varargs: bool = False) -> AST.ASTTypFun:
        return self.astree.mk_function_with_arguments_type(
            returntype, arguments, varargs=varargs)

    def __str__(self) -> str:
        lines: List[str] = []
        for r in self.astree.spans:
            lines.append(str(r))
        return "\n".join(lines)
