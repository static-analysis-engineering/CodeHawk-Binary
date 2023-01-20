# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs LLC
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
from chb.ast.ASTByteSizeCalculator import ASTByteSizeCalculator
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


if TYPE_CHECKING:
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

"""fname -> registers/stack -> name/offset -> [span/altname -> (low, high), name]."""
VariableNamesRec = NewType(
    "VariableNamesRec",
    Dict[str, Dict[str, Dict[str, List[Dict[str, Union[Tuple[str, str], str]]]]]])

variable_intro: Dict[str, str] = {
    "0x11d46": "size",
    "0x11d8c": "size"
}

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


class ASTInterface:

    def __init__(
            self,
            astree: AbstractSyntaxTree,
            typconverter: "BC2ASTConverter",
            parameter_abi: str,
            srcprototype: Optional["BCVarInfo"] = None,
            astprototype: Optional[AST.ASTVarInfo] = None,
            varintros: Dict[str, str] = {},
            verbose: bool = False,
            showdiagnostics: bool = False) -> None:
        self._astree = astree
        self._srcprototype = srcprototype
        self._astprototype = astprototype
        self._varintros = varintros
        self._typconverter = typconverter
        self._verbose = verbose
        self._showdiagnostics = showdiagnostics
        self._ctyper = ASTBasicCTyper(astree.globalsymboltable)
        self._bytesizecalculator = ASTByteSizeCalculator(
            self._ctyper,
            structsizes=self._typconverter.structsizes)
        self._parameter_abi = parameter_abi
        self._srcformals: List[ASTIFormalVarInfo] = []
        self._unsupported: Dict[str, List[str]] = {}
        self._annotations: Dict[int, List[str]] = {}
        self._diagnostics: List[str] = []
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
    def varintros(self) -> Dict[str, str]:
        return self._varintros

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
    def showdiagnostics(self) -> bool:
        return self._showdiagnostics

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
    def diagnostics(self) -> List[str]:
        return self._diagnostics

    def add_diagnostic(self, msg: str) -> None:
        self._diagnostics.append(msg)

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
        for r in ["R0", "R1", "R2", "R3", "R4", "R5", "R6", "R7"]:
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

    @property
    def fname(self) -> str:
        return self.astree.fname

    @property
    def symboltable(self) -> ASTLocalSymbolTable:
        return self.astree.symboltable

    @property
    def globalsymboltable(self) -> ASTGlobalSymbolTable:
        return self.symboltable.globaltable

    def compinfo(self, ckey: int) -> AST.ASTCompInfo:
        return self.globalsymboltable.compinfo(ckey)

    def type_size_in_bytes(self, typ: AST.ASTTyp) -> int:
        return typ.index(self.bytesize_calculator)

    def resolve_type(self, t: AST.ASTTyp) -> AST.ASTTyp:
        if t.is_typedef:
            t = cast(AST.ASTTypNamed, t)
            return self.globalsymboltable.resolve_typedef(t.typname)
        else:
            return t

    @property
    def spans(self) -> List[ASTSpanRecord]:
        return self.astree.spans

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
            self.add_diagnostic("No source prototype found")

    def global_symbols(self) -> Sequence[AST.ASTVarInfo]:
        return []
        # return self.symboltable.global_symbols()

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

    def function_argument(self, index: int) -> List[AST.ASTLval]:
        """Return the argument(s) with the given index (zero-based).

        There may be more than one argument, in case of a packed array.
        """

        if len(self.srcformals) > 0:
            (formal, locindices) = self.get_formal_locindices(index)
            regvar = AST.ASTVariable(formal.lifted_vinfo)
            lvals: List[AST.ASTLval] = []
            for locindex in locindices:
                (loc, offset, size) = formal.argloc(locindex)
                lvals.append(self.mk_lval(regvar, offset))
            return lvals
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
            optlocationid: Optional[int] = None) -> AST.ASTLoop:
        return self.astree.mk_loop(body, optlocationid=optlocationid)

    def mk_return_stmt(
            self,
            expr: Optional[AST.ASTExpr],
            iaddr: Optional[str] = None,
            bytestring: Optional[str] = None,
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTReturn:
        if expr is not None and iaddr is not None and bytestring is not None:
            self.astree.add_expr_span(expr.exprid, iaddr, bytestring)
        return self.astree.mk_return_stmt(expr, labels=labels)

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
            optlocationid: Optional[int] = None) -> AST.ASTStmt:
        return self.astree.mk_branch(
            condition,
            ifbranch,
            elsebranch,
            targetaddr,
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
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTGoto:
        return self.astree.mk_goto_stmt(name, destaddr, labels=labels)

    def mk_switch_stmt(
            self,
            switchexpr: Optional[AST.ASTExpr],
            cases: AST.ASTStmt,
            optlocationid: Optional[int] = None,
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTSwitchStmt:
        return self.astree.mk_switch_stmt(
            switchexpr, cases, optlocationid=optlocationid, labels=labels)

    # ---------------------------------------------------- make labels ---------

    def mk_label(self, name: str) -> AST.ASTLabel:
        return self.astree.mk_label(name)

    def mk_case_label(self, expr: Optional[AST.ASTExpr]) -> AST.ASTCaseLabel:
        return self.astree.mk_case_label(expr)

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
            bytestring: Optional[str] = None) -> AST.ASTCall:
        call = self.astree.mk_call(lval, tgt, args)
        if iaddr is not None and bytestring is not None:
            self.add_instruction_span(call.locationid, iaddr, bytestring)
        return call

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

    def mk_returnval_variable(
            self,
            iaddr: str,
            vtype: Optional[AST.ASTTyp]) -> AST.ASTVariable:
        name = "rtn_" + iaddr
        return self.mk_named_variable(name, vtype=vtype)

    def mk_returnval_variable_lval(
            self,
            iaddr: str,
            vtype: Optional[AST.ASTTyp],
            anonymous: bool = False) -> AST.ASTLval:
        var = self.mk_returnval_variable(iaddr, vtype)
        return self.mk_lval(var, nooffset, anonymous=anonymous)

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

    def mk_stack_variable(
            self,
            offset: int,
            name: Optional[str] = None,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None) -> AST.ASTVariable:
        if name is None:
            if offset < 0:
                name = "localvar_" + str(-offset)
            elif offset == 0:
                name = "localvar_0"
            else:
                name = "argvar_" + str(offset)
        return self.mk_named_variable(name, vtype=vtype, parameter=parameter)

    def mk_stack_variable_lval(
            self,
            offset: int,
            optname: Optional[str] = None,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            storage_size: Optional[int] = None,
            anonymous: bool = False) -> AST.ASTLval:
        if optname is None:
            if offset < 0:
                name = "localvar_" + str(-offset)
            else:
                name = "argvar_" + str(offset)
        else:
            name = optname
        optlvalid = -1 if anonymous else None
        return self.astree.mk_stack_variable_lval(
            name, offset, vtype=vtype, parameter=parameter, optlvalid=optlvalid)

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
                raise UF.CHBError("add_ot_index_offset: not yet supported")

    def mk_integer_constant(self, cvalue: int) -> AST.ASTIntegerConstant:
        return self.astree.mk_integer_constant(cvalue)

    def mk_float_constant(self, fvalue: float) -> AST.ASTFloatingPointConstant:
        return self.astree.mk_float_constant(fvalue)

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

    '''
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
    '''

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
    '''
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
    '''

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

    # ---------------------------------------------------- AST rewriting ---

    '''
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
            block.assembly_xref, [self.rewrite_stmt(s) for s in block.stmts])

    def rewrite_branch(self, branch: AST.ASTBranch) -> AST.ASTStmt:
        return AST.ASTBranch(
            branch.assembly_xref,
            self.rewrite_expr(branch.condition),
            self.rewrite_stmt(branch.ifstmt),
            self.rewrite_stmt(branch.elsestmt),
            branch.relative_offset)

    def rewrite_instruction_sequence(
            self, instrseq: AST.ASTInstrSequence) -> AST.ASTStmt:
        return AST.ASTInstrSequence(
            instrseq.assembly_xref,
            [self.rewrite_instruction(i) for i in instrseq.instructions])

    def rewrite_instruction(self, instr: AST.ASTInstruction) -> AST.ASTInstruction:
        if instr.is_ast_assign:
            return self.rewrite_assign(cast(AST.ASTAssign, instr))
        if instr.is_ast_call:
            return self.rewrite_call(cast(AST.ASTCall, instr))

        return instr

    def rewrite_assign(self, assign: AST.ASTAssign) -> AST.ASTInstruction:
        return AST.ASTAssign(
            assign.assembly_xref,
            self.rewrite_lval(assign.lhs),
            self.rewrite_expr(assign.rhs),
            annotations=assign.annotations)

    def rewrite_call(self, call: AST.ASTCall) -> AST.ASTInstruction:
        return call

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
    '''

    def __str__(self) -> str:
        lines: List[str] = []
        for r in self.astree.spans:
            lines.append(str(r))
        return "\n".join(lines)
