# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2025  Aarno Labs LLC
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
    Set,
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

from chb.userdata.UserHints import (
    FunctionAnnotation, RegisterVarIntro, StackVarIntro)

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger


if TYPE_CHECKING:
    from chb.api.AppFunctionSignature import AppFunctionSignature
    from chb.app.FnStackFrame import FnStackFrame
    from chb.astinterface.BC2ASTConverter import BC2ASTConverter
    from chb.bctypes.BCConverter import BCConverter
    from chb.bctypes.BCFieldInfo import BCFieldInfo
    from chb.bctypes.BCFunArgs import BCFunArg
    from chb.bctypes.BCFunctionDefinition import BCFunctionDefinition
    from chb.bctypes.BCTyp import BCTyp, BCTypFun, BCTypComp, BCTypArray, BCTypPtr
    from chb.bctypes.BCVarInfo import BCVarInfo
    from chb.cmdline.PatchResults import PatchEvent
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
            functionannotation: Optional[FunctionAnnotation] = None,
            stackvarintros: Dict[int, str] = {},
            patchevents: Dict[str, "PatchEvent"] = {},
            verbose: bool = False) -> None:
        self._astree = astree
        self._srcprototype = srcprototype
        self._astprototype = astprototype
        self._appsignature = appsignature
        self._rdeflocs = rdeflocs
        self._functionannotation = functionannotation
        self._varintros = varintros
        self._stackvarintros = stackvarintros
        self._patchevents = patchevents
        self._typconverter = typconverter
        self._verbose = verbose
        self._ctyper = ASTBasicCTyper(astree.globalsymboltable)
        self._bytesizecalculator = ASTByteSizeCalculator(
            self._ctyper,
            structsizes=self._typconverter.structsizes)
        self._parameter_abi = parameter_abi
        self._srcformals: List[ASTIFormalVarInfo] = []
        self._ssa_prefix_counters: Dict[str, int] = {}
        self._ssa_intros: Dict[str, Dict[str, AST.ASTVarInfo]] = {}
        self._ssa_values: Dict[str, AST.ASTExpr] = {}
        self._ssa_addresses: Dict[str, Set[str]] = {}
        self._stack_varinfos: Dict[int, AST.ASTVarInfo] = {}
        self._stack_variables: Dict[int, AST.ASTLval] = {}
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
    def function_annotation(self) -> Optional[FunctionAnnotation]:
        return self._functionannotation

    def has_function_annotation(self) -> bool:
        return self.function_annotation is not None

    # deprecated
    @property
    def varintros(self) -> Dict[str, str]:
        return self._varintros

    # deprecated
    @property
    def stackvarintros(self) -> Dict[int, str]:
        return self._stackvarintros

    @property
    def patchevents(self) -> Dict[str, "PatchEvent"]:
        return self._patchevents

    def is_in_wrapper(self, addr: str) -> bool:
        for p in self. patchevents.values():
            if p.in_wrapper(addr):
                return True
        return False

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

    def has_function_prototype(self) -> bool:
        return self.astree.has_function_prototype()

    @property
    def function_prototype(self) -> Optional[AST.ASTVarInfo]:
        return self.astree.function_prototype

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

    # deprecated
    def has_variable_intro(self, iaddr: str) -> bool:
        return iaddr in self.varintros

    # deprecated
    def get_variable_intro(self, iaddr: str) -> str:
        if self.has_variable_intro(iaddr):
            return self.varintros[iaddr]
        else:
            raise UF.CHBError("No variable intro found for " + iaddr)

    def has_register_variable_intro(self, iaddr: str) -> bool:
        fnannotation = self.function_annotation
        if fnannotation is not None:
            return fnannotation.has_register_variable_introduction(iaddr)
        return False

    def get_register_variable_intro(self, iaddr: str) -> RegisterVarIntro:
        fnannotation = self.function_annotation
        if fnannotation is not None:
            return fnannotation.get_register_variable_introduction(iaddr)
        raise UF.CHBError("No function annotation found")

    def has_stack_variable_intro(self, offset: int) -> bool:
        fnannotation = self.function_annotation
        if fnannotation is not None:
            return fnannotation.has_stack_variable_introduction(offset)
        return False

    def get_stack_variable_intro(self, offset: int) -> StackVarIntro:
        fnannotation = self.function_annotation
        if fnannotation is not None:
            return fnannotation.get_stack_variable_introduction(offset)
        raise UF.CHBError("No function annotation found")

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

        if uses is not None:
            uselocs = [str(x) for x in uses.uselocations]
            if len(uselocs) == 1 and self.is_in_wrapper(uselocs[0]):
                chklogger.logger.info(
                    "Filter out use-high location %s in wrapper for %s",
                    str(uselocs[0]), str(lval))
                return

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

    @property
    def global_addresses(self) -> Mapping[str, AST.ASTVarInfo]:
        return self.globalsymboltable.symbolic_addresses

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
        # return self.symboltable.global_symbols()
        return []

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
        self.astree.add_span(span)

    def add_stmt_span(self, id: int, spans: List[Tuple[str, str]]) -> None:
        self.astree.add_stmt_span(id, spans)

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
            offset: AST.ASTOffset = nooffset,
            globaladdress: int = 0,
            llref: bool = False,
            anonymous: bool = False) -> AST.ASTExpr:
        return self.astree.mk_named_lval_expression(
            name,
            offset=offset,
            vtype=vtype,
            globaladdress=globaladdress,
            llref=llref,
            anonymous=anonymous)

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
            offset=offset,
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
    def ssa_values(self) -> Dict[str, AST.ASTExpr]:
        """Return ssa vname -> constant value assigned to ssa variable."""

        return self._ssa_values

    @property
    def stack_variables(self) -> Dict[int, AST.ASTLval]:
        """Return a map from stack offset in bytes to lval at that offset.

        This map includes all lvals to the lowest granularity, including fields
        and array elements. The latter are represented in the offset of the lval
        returned.

        Note: currently this is not yet fully recursive, so if the field
        itself is a struct, this struct will be returned rather than the
        field of that struct, and so on.
        """

        return self._stack_variables

    @property
    def stack_varinfos(self) -> Dict[int, AST.ASTVarInfo]:
        """Return a map from stack offset in bytes to varinfo at that offset.

        This map differs from the stack_variables map in that only top-level
        variables are included (i.e., the ones that are declared in the
        function.

        Note that for structs this map returns the struct, while the
        stack_variables map will return the first field of the struct.
        """

        return self._stack_varinfos

    def introduce_ssa_variables(
            self,
            rdeflocs: Dict[str, List[List[str]]],
            ftypes: Dict[str, Dict[str, "BCTyp"]],
            ssanames: Dict[str, str] = {}) -> None:
        """Creates ssa variables based on reaching definition locations.

        Lists with multiple locations will give rise to a single variable
        being created for all of those locations, as these all reach a
        particular use of the variable.

        Record addresses associated with a given variable to avoid assigning
        constants to variables that appear multiple times.

        The ssanames, a map from locations to names, provide an alternative
        prefix for the newly introduced name. The default name is ssa_<reg>,
        where <reg> is the name of the register being assigned.
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
                    vinfo = self.mk_ssa_register_varinfo(
                        reg, loc1, vtype=vtype, prefix=ssanames.get(loc1))
                    self._ssa_addresses.setdefault(vinfo.vname, set([]))
                    for loc in lst:
                        self._ssa_intros.setdefault(loc, {})
                        self._ssa_intros[loc][reg] = vinfo
                        self._ssa_addresses[vinfo.vname].add(loc)

    def introduce_stack_variables(
            self,
            stackframe: "FnStackFrame",
            stackvartypes: Dict[int, "BCTyp"]) -> None:
        """Creates stack variables/buffers for all stack offsets with types."""

        # local variable stack offsets from the type inference are positive,
        # so they must be negated here. For the same reason, to capture the
        # largest extent of every varinfo, offsets must be traversed in reverse
        # order.
        for (offset, bctype) in sorted(stackvartypes.items(), reverse=True):
            offset = -offset
            vtype = bctype.convert(self.typconverter)

            # if the type is an array, its size may have to be adjusted based
            # on the stacklayout determined in FnStackFrame.
            if vtype.is_array:
                vtype = cast(AST.ASTTypArray, vtype)
                if vtype.has_constant_size() and vtype.size_value() == 1:
                    buffer = stackframe.get_stack_buffer(offset)
                    if buffer is not None:
                        size = buffer.size
                        tgttyp = vtype.tgttyp
                        tgttypsize = tgttyp.index(self.bytesize_calculator)
                        if tgttypsize > 0:
                            arraysize = size // tgttypsize
                            if arraysize == 1:
                                vtype = tgttyp
                            if arraysize > 1:
                                vtype = self.astree.mk_int_sized_array_type(
                                    tgttyp, arraysize)
                            else:
                                chklogger.logger.info(
                                    "Array size for stack variable at offset "
                                    + "%s does not fit in stack frame; "
                                    + "adjusting stack buffer to size %d",
                                    str(offset), tgttypsize)
                                vtype = tgttyp

            self.mk_stack_variable_lval(offset, vtype=vtype)

    def mk_ssa_register_varinfo(
            self,
            name: str,
            iaddr: str,
            vtype: Optional[AST.ASTTyp] = None,
            prefix: Optional[str] = None,
            save_loc: bool = False) -> AST.ASTVarInfo:
        if iaddr in self.ssa_intros and name in self.ssa_intros[iaddr]:
            vinfo = self.ssa_intros[iaddr][name]
            if vtype is not None and vinfo.vtype is None:
                vinfo.vtype = vtype
            return vinfo

        # create a new ssa variable
        if self.has_register_variable_intro(iaddr):
            vname = self.get_register_variable_intro(iaddr).name
        elif prefix is not None:
            self._ssa_prefix_counters.setdefault(prefix, 0)
            ssaid = self._ssa_prefix_counters[prefix]
            self._ssa_prefix_counters[prefix] += 1
            vname = prefix + "__" + str(ssaid)
        else:
            ssaprefix = "ssa_" + name
            self._ssa_prefix_counters.setdefault(ssaprefix, 0)
            ssaid = self._ssa_prefix_counters[ssaprefix]
            self._ssa_prefix_counters[ssaprefix] += 1
            vname = ssaprefix + "_" + str(ssaid)
        varinfo = self.add_symbol(vname, vtype=vtype)
        self._ssa_intros.setdefault(iaddr, {})
        self._ssa_intros[iaddr][name] = varinfo
        if save_loc:
            self._ssa_addresses.setdefault(varinfo.vname, set([]))
            self._ssa_addresses[varinfo.vname].add(iaddr)
            chklogger.logger.info(
                "On the fly addition of ssa variable %s for address %s",
                varinfo.vname, iaddr)
        return varinfo

    def set_ssa_value(self, name: str, value: AST.ASTExpr) -> None:
        if len(self._ssa_addresses[name]) > 1:
            chklogger.logger.info(
                "Unable to set ssa value for %s due to multiple variable "
                + "instances: {%s}",
                name,
                ", ".join(str(x) for x in self._ssa_addresses[name]))
        else:
            self._ssa_values[name] = value

    def get_ssa_value(self, name: str) -> Optional[AST.ASTExpr]:
        return self.ssa_values.get(name, None)

    def has_ssa_value(self, name: str) -> bool:
        return name in self._ssa_values

    def mk_stack_variable_lval(
            self, offset: int, vtype: Optional[AST.ASTTyp]=None) -> AST.ASTLval:

        # Update varinfo type with vtype if existing varinfo vtype is None
        if offset in self.stack_varinfos and vtype is not None:
            if self.stack_varinfos[offset].vtype is None:
                self.stack_varinfos[offset].vtype = vtype

            return self.stack_variables[offset]

        if offset in self.stack_variables:
            return self.stack_variables[offset]

        # create a new stack variable
        if self.has_stack_variable_intro(offset):
            svintro = self.get_stack_variable_intro(offset)
            vname = svintro.name
        else:
            if offset < 0:
                vname = "localstackvar_" + str(-offset)
            else:
                vname = "stack_" + str(offset)

        size: Optional[int] = None
        if vtype is not None:
            size = self.type_size_in_bytes(vtype)
        varinfo = self.add_symbol(vname, vtype=vtype)
        self._stack_varinfos[offset] = varinfo

        storage = self.astree.mk_stack_storage(offset, size)
        lval = self.astree.mk_vinfo_lval(varinfo, storage=storage)
        self._stack_variables[offset] = lval

        if varinfo.vtype is None:
            return lval

        if varinfo.vtype.is_compound:
            structtyp = cast(AST.ASTTypComp, varinfo.vtype)
            ckey = structtyp.compkey
            compinfo = self.globalsymboltable.compinfo(ckey)
            for (cfoff, fname) in sorted(compinfo.field_offsets.items()):
                fieldoffset = self.mk_field_offset(fname, ckey)
                fieldlval = self.astree.mk_vinfo_lval(
                    varinfo, offset=fieldoffset)
                self.stack_variables[offset + cfoff] = fieldlval
            return lval

        if varinfo.vtype.is_array:
            arraytyp = cast(AST.ASTTypArray, varinfo.vtype)
            eltyp = arraytyp.tgttyp
            elsize = self.type_size_in_bytes(eltyp)
            if elsize is None:
                chklogger.logger.warning(
                    "Unable to lay out stack array %s at offset %s due to "
                    + "missing element size",
                    str(varinfo), str(offset))
                return lval

            if arraytyp.has_constant_size():
                arraysize = arraytyp.size_value()
            else:
                chklogger.logger.warning(
                    "Assuming array size 1 for array %s with unknown size "
                    + "at offset %s",
                    str(varinfo), str(offset))
                arraysize = 1
            if eltyp.is_compound:
                structtyp = cast(AST.ASTTypComp, eltyp)
                ckey = structtyp.compkey
                compinfo = self.globalsymboltable.compinfo(ckey)
                elementoffset = offset
                for i in range(arraysize):
                    for (cfoff, fname) in sorted(compinfo.field_offsets.items()):
                        fieldoffset = self.mk_field_offset(fname, ckey)
                        indexoffset = self.mk_scalar_index_offset(i, fieldoffset)
                        fieldlval = self.astree.mk_vinfo_lval(
                            varinfo, offset=indexoffset)
                        self._stack_variables[elementoffset + cfoff] = fieldlval
                    elementoffset += elsize

        return lval



    def mk_stackvarinfo_offset(
            self, offset: int, vtype: Optional[AST.ASTTyp]) -> None:
        """Creates a new stack variable if none exists at offset.

        If the offset is already covered by another stack variable, it
        determines the offset within the existing variable and records this
        in the stack_variables data field (if not already present).
        Otherwise it creates a new stack variable, and, in case of a struct
        variable, also creates entries for the fields.
        """
        pass

    def mk_ssa_register_variable(
            self,
            name: str,
            iaddr: str,
            vtype: Optional[AST.ASTTyp] = None) -> AST.ASTVariable:
        varinfo = self.mk_ssa_register_varinfo(
            name, iaddr, vtype=vtype, save_loc=True)
        return AST.ASTVariable(varinfo)

    def mk_ssa_register_variable_lval(
            self,
            name: str,
            iaddr: str,
            vtype: Optional[AST.ASTTyp] = None,
            ssavalue: Optional[AST.ASTExpr] = None) -> AST.ASTLval:
        vinfo = self.mk_ssa_register_varinfo(
            name, iaddr, vtype=vtype, save_loc=True)
        storage = self.astree.mk_register_storage(name)
        if ssavalue is not None:
            self.set_ssa_value(vinfo.vname, ssavalue)
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

    def mk_temp_lval_expression(self) -> AST.ASTExpr:
        return self.astree.mk_tmp_lval_expression()

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
            if (
                    baseoffset.index_expr.is_integer_constant
                    and baseoffset.offset.is_no_offset):
                baseindex = cast(AST.ASTIntegerConstant, baseoffset.index_expr)
                newindex = baseindex.cvalue + increm
                return self.mk_scalar_index_offset(newindex)
            else:
                raise UF.CHBError("add_to_index_offset: not yet supported")

    def mk_integer_constant(
            self, cvalue: int, ikind: str = "iint") -> AST.ASTIntegerConstant:
        return self.astree.mk_integer_constant(cvalue, ikind=ikind)

    def mk_float_constant(
            self,
            fvalue: float,
            fkind: str = "float") -> AST.ASTFloatingPointConstant:
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
            self, lval: AST.ASTLval, anonymous: bool = False) -> AST.ASTExpr:
        optexprid = -1 if anonymous else None
        if lval.offset.tail_offset.is_index_offset:
            indexexpr = cast(
                AST.ASTIndexOffset, lval.offset.tail_offset).index_expr
            if indexexpr.is_integer_constant_zero:
                return self.mk_index_parent_start_of(lval)

        return self.astree.mk_address_of_expression(lval, optexprid=optexprid)

    def mk_index_parent_start_of(self, lval: AST.ASTLval) -> AST.ASTStartOf:

        def replace_tail(offset: AST.ASTOffset) -> AST.ASTOffset:
            if offset.is_no_offset:
                chklogger.logger.error("Inconsistent offset")
                return offset
            elif offset.is_field_offset:
                offset = cast(AST.ASTFieldOffset, offset)
                suboffset = replace_tail(offset.offset)
                return self.mk_field_offset(
                    offset.fieldname, offset.compkey, offset = suboffset)
            else:
                if offset.offset.is_no_offset:
                    return offset.offset
                else:
                    offset = cast(AST.ASTIndexOffset, offset)
                    suboffset = replace_tail(offset.offset)
                    return self.mk_expr_index_offset(
                        offset.index_expr, offset=suboffset)

        lval = self.mk_lval(lval.lhost, replace_tail(lval.offset))
        return self.mk_start_of(lval)

    def mk_start_of(self, lval: AST.ASTLval) -> AST.ASTStartOf:
        return self.astree.mk_start_of_expression(lval, optexprid=None)

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

    def convert_void_pointer(self, t: AST.ASTTyp) -> AST.ASTTyp:
        if t.is_void_pointer:
            return self.astree.mk_pointer_type(self.astree.unsigned_char_type)
        else:
            return t

    def __str__(self) -> str:
        lines: List[str] = []
        for r in self.astree.spans:
            lines.append(str(r))
        return "\n".join(lines)
