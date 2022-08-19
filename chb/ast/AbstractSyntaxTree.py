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
    Set,
    Tuple,
    TYPE_CHECKING,
    Union)

import chb.ast.ASTNode as AST
from chb.ast.ASTProvenance import ASTProvenance
from chb.ast.ASTSerializer import ASTSerializer

from chb.ast.ASTStorage import (
    ASTStorage,
    ASTRegisterStorage,
    ASTFlagStorage,
    ASTStackStorage,
    ASTBaseStorage,
    ASTGlobalStorage,
    ASTStorageConstructor)

from chb.ast.ASTSymbolTable import (
    ASTGlobalSymbolTable, ASTSymbolTable, ASTLocalSymbolTable)


ASTSpanRecord = NewType(
    "ASTSpanRecord", Dict[str, Union[int, List[Dict[str, Union[str, int]]]]])


nooffset = AST.ASTNoOffset()
voidtype = AST.ASTTypVoid()


class AbstractSyntaxTree:

    def __init__(
            self,
            faddr: str,
            fname: str,
            localsymboltable: ASTLocalSymbolTable,
            registersizes: Dict[str, int] = {},
            flagnames: List[str] = [],
            defaultsize: Optional[int] =  None) -> None:
        self._faddr = faddr
        self._fname = fname  # same as faddr if no name provided
        self._stmtid_counter = 1
        self._instrid_counter =  1
        self._locationid_counter = 1
        self._lval_counter = 1
        self._expr_counter = 1
        self._tmpcounter = 0
        self._spans: List[ASTSpanRecord] = []
        self._storage: Dict[int, ASTStorage] = {}
        self._instructionmapping: Dict[int, List[int]] = {}
        self._expressionmapping: Dict[int, List[int]] = {}
        self._reachingdefinitions: Dict[int, List[int]] = {}
        self._available_expressions: Dict[str, Dict[str, Tuple[int, int, str]]] = {}
        self._symboltable = localsymboltable
        self._storageconstructor = ASTStorageConstructor(
            registersizes, defaultsize, flagnames)
        self._provenance = ASTProvenance()
        self._serializer = ASTSerializer()

        # integer types
        self._char_type = self.mk_integer_ikind_type("ichar")
        self._signed_char_type = self.mk_integer_ikind_type("ischar")
        self._unsigned_char_type = self.mk_integer_ikind_type("iuchar")
        self._bool_type = self.mk_integer_ikind_type("ibool")
        self._int_type = self.mk_integer_ikind_type("iint")
        self._unsigned_int_type = self.mk_integer_ikind_type("iuint")
        self._short_type = self.mk_integer_ikind_type("ishort")
        self._unsigned_short_type = self.mk_integer_ikind_type("iushort")
        self._long_type = self.mk_integer_ikind_type("ilong")
        self._unsigned_long_type = self.mk_integer_ikind_type("iulong")
        self._long_long_type = self.mk_integer_ikind_type("ilonglong")
        self._unsigned_long_long_type = self.mk_integer_ikind_type("iulonglong")

        # float types
        self._float_type = self.mk_float_fkind_type("float")
        self._double_type = self.mk_float_fkind_type("fdouble")
        self._long_double_type = self.mk_float_fkind_type("flongdouble")

    @property
    def fname(self) -> str:
        return self._fname

    @property
    def faddr(self) -> str:
        return self._faddr

    @property
    def symboltable(self) -> ASTLocalSymbolTable:
        return self._symboltable

    @property
    def globalsymboltable(self) -> ASTGlobalSymbolTable:
        return self.symboltable.globaltable

    @property
    def compinfos(self) -> Mapping[int, AST.ASTCompInfo]:
        return self.symboltable.compinfos

    @property
    def provenance(self) -> ASTProvenance:
        return self._provenance

    @property
    def serializer(self) -> ASTSerializer:
        return self._serializer

    @property
    def spans(self) -> List[ASTSpanRecord]:
        return self._spans

    @property
    def storage(self) -> Dict[int, ASTStorage]:
        return self._storage

    @property
    def available_expressions(
            self) -> Dict[str, Dict[str, Tuple[int, int, str]]]:
        return self._available_expressions

    def set_available_expressions(
            self,
            aexprs: Dict[str, Dict[str, Tuple[int, int, str]]]) -> None:
        self._available_expressions = aexprs

    @property
    def instructionmapping(self) -> Dict[int, List[int]]:
        return self._instructionmapping

    def addto_instruction_mapping(
            self,
            high_level_instrid: int,
            low_level_instrids: List[int]) -> None:
        entry = self.instructionmapping.setdefault(high_level_instrid, [])
        for llid in low_level_instrids:
            if llid not in entry:
                entry.append(llid)
        self.instructionmapping[high_level_instrid] = entry

    @property
    def reachingdefinitions(self) -> Dict[int, List[int]]:
        return self._reachingdefinitions

    def addto_reaching_definitions(
            self,
            exprid: int,
            instrids: List[int]) -> None:
        entry = self.reachingdefinitions.setdefault(exprid, [])
        for instrid in instrids:
            if instrid not in entry:
                entry.append(instrid)
        self.reachingdefinitions[exprid] = entry

    @property
    def expressionmapping(self) -> Dict[int, List[int]]:
        return self._expressionmapping

    def addto_expression_mapping(
            self,
            src_exprid: int,
            dst_exprids: List[int]) -> None:
        entry = self.expressionmapping.setdefault(src_exprid, [])
        for x in dst_exprids:
            if x not in entry:
                entry.append(x)
        self.expressionmapping[src_exprid] = entry

    def storage_records(self) -> Dict[int, Dict[str, Union[str, int]]]:
        results: Dict[int, Dict[str, Union[str, int]]] = {}
        for (lvalid, record) in self.storage.items():
            results[lvalid] = record.serialize()
        return results

    @property
    def storageconstructor(self) -> ASTStorageConstructor:
        return self._storageconstructor

    def set_function_prototype(self, p: AST.ASTVarInfo) -> None:
        self.symboltable.set_function_prototype(p)

    def has_symbol(self, name: str) -> bool:
        return self.symboltable.has_symbol(name)

    def get_symbol(self, name: str) -> AST.ASTVarInfo:
        return self.symboltable.get_symbol(name)

    def add_symbol(
            self,
            name: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> AST.ASTVarInfo:
        return self.symboltable.add_symbol(
            name,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr)

    def add_compinfo(self, cinfo: AST.ASTCompInfo) -> None:
        self.symboltable.add_compinfo(cinfo)

    def new_stmtid(self) -> int:
        """Return a new id for statements."""

        stmtid = self._stmtid_counter
        self._stmtid_counter += 1
        return stmtid

    def get_stmtid(self, stmtid: Optional[int]) -> int:
        return self.new_stmtid() if stmtid is None else stmtid

    def new_instrid(self) -> int:
        """Return a new id for instructions."""

        instrid = self._instrid_counter
        self._instrid_counter += 1
        return instrid

    def get_instrid(self, instrid: Optional[int]) -> int:
        return self.new_instrid() if instrid is None else instrid

    def new_locationid(self) -> int:
        """Return a new location id for statements/labels/instructions."""

        locationid = self._locationid_counter
        self._locationid_counter += 1
        return locationid

    def get_locationid(self, locationid: Optional[int]) -> int:
        return self.new_locationid() if locationid is None else locationid

    def new_lvalid(self) -> int:
        """Return a new lval id for lvalues."""

        lvalid = self._lval_counter
        self._lval_counter += 1
        return lvalid

    def get_lvalid(self, lvalid: Optional[int]) -> int:
        return self.new_lvalid() if lvalid is None else lvalid

    def new_exprid(self) -> int:
        """Return a new expression id."""

        exprid = self._expr_counter
        self._expr_counter += 1
        return exprid

    def get_exprid(self, exprid: Optional[int]) -> int:
        return self.new_exprid() if exprid is None else exprid

    def add_span(self, span: ASTSpanRecord) -> None:
        self._spans.append(span)

    def add_instruction_span(
            self, locationid: int, base: str, bytestring: str) -> None:
        span: Dict[str, Union[str, int]] = {}
        span["base_va"] = base
        span["size"] = len(bytestring) // 2
        spanrec: Dict[str, Any] = {}
        spanrec["locationid"] = locationid
        spanrec["spans"] = [span]
        self.add_span(cast(ASTSpanRecord, spanrec))

    def spanmap(self) -> Dict[int, str]:
        """Return mapping from locationid to instruction base address."""

        result: Dict[int, str] = {}
        for spanrec in self.spans:
            spanlocationid = cast(int, spanrec["locationid"])
            spans_at_xref = cast(List[Dict[str, Any]], spanrec["spans"])
            result[spanlocationid] = spans_at_xref[0]["base_va"]
        return result

    # ------------------------------------------------------ make statements ---

    def mk_block(
            self,
            stmts: List[AST.ASTStmt],
            optstmtid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTBlock:
        stmtid = self.get_stmtid(optstmtid)
        locationid = self.get_locationid(optlocationid)
        return AST.ASTBlock(stmtid, locationid, stmts, labels=labels)

    def mk_return_stmt(
            self,
            expr: Optional[AST.ASTExpr],
            optstmtid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTReturn:
        stmtid = self.get_stmtid(optstmtid)
        locationid = self.get_locationid(optlocationid)
        return AST.ASTReturn(stmtid, locationid, expr, labels=labels)

    def mk_loop(
            self,
            body: AST.ASTStmt,
            optstmtid: Optional[int] = None,
            optlocationid: Optional[int] = None) -> AST.ASTLoop:
        stmtid = self.get_stmtid(optstmtid)
        locationid = self.get_locationid(optlocationid)
        return AST.ASTLoop(stmtid, locationid, body)


    def mk_break_stmt(
            self,
            optstmtid: Optional[int] = None,
            optlocationid: Optional[int] = None) -> AST.ASTBreak:
        stmtid = self.get_stmtid(optstmtid)
        locationid = self.get_locationid(optlocationid)
        return AST.ASTBreak(stmtid, locationid)

    def mk_continue_stmt(
            self,
            optstmtid: Optional[int] = None,
            optlocationid: Optional[int] = None) -> AST.ASTContinue:
        stmtid = self.get_stmtid(optstmtid)
        locationid = self.get_locationid(optlocationid)
        return AST.ASTContinue(stmtid, locationid)

    def mk_branch(
            self,
            condition: Optional[AST.ASTExpr],
            ifbranch: AST.ASTStmt,
            elsebranch: AST.ASTStmt,
            targetaddr: str,
            optstmtid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTStmt:
        stmtid = self.get_stmtid(optstmtid)
        locationid = self.get_locationid(optlocationid)
        if condition is None:
            # create a new unknown (uninitialized) variable
            condition = self.mk_tmp_lval_expression()
        return AST.ASTBranch(
            stmtid, locationid, condition, ifbranch, elsebranch, targetaddr)

    def mk_goto_stmt(
            self,
            destinationlabel: str,
            destinationaddr: str,
            optstmtid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTGoto:
        stmtid = self.get_stmtid(optstmtid)
        locationid = self.get_locationid(optlocationid)
        return AST.ASTGoto(stmtid, locationid, destinationlabel, destinationaddr)

    def mk_switch_stmt(
            self,
            switchexpr: Optional[AST.ASTExpr],
            cases: AST.ASTStmt,
            optstmtid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTSwitchStmt:
        if switchexpr is None:
            # create a new unknown (uninitialized) variable
            switchexpr = self.mk_tmp_lval_expression()
        stmtid = self.get_stmtid(optstmtid)
        locationid = self.get_locationid(optlocationid)
        return AST.ASTSwitchStmt(
            stmtid, locationid, switchexpr, cases, labels=labels)

    def mk_instr_sequence(
            self,
            instrs: List[AST.ASTInstruction],
            optstmtid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            labels: List[AST.ASTStmtLabel] = []) -> AST.ASTInstrSequence:
        stmtid = self.get_stmtid(optstmtid)
        locationid = self.get_locationid(optlocationid)
        return AST.ASTInstrSequence(stmtid, locationid, instrs, labels=labels)


    """Labels
    Labels can be associated with statements. They represent both to mark
    a location in the control-flow, for example serving as the destination
    of a goto statement, and to specify case label in a switch statement.
    Labels have a locationid associated with them.

    Construction methods provided:
    ------------------------------
    - mk_label: creates a marker label with a name that can be used as the
        destination of a goto statement

    - mk_case_label: creates a case label for a switch statement with a
        case expression

    - mk_case_range_label: creates a case label for a switch statement with
        a range of expressions, expressed as lowexpr and a highexpr
        (this is a gcc extension, not part of the C standard)

    - mk_default_label: creates a default label for a switch statement.
    """

    def mk_label(
            self, name: str, optlocationid: Optional[int]=None) -> AST.ASTLabel:
        locationid = self.get_locationid(optlocationid)
        return AST.ASTLabel(locationid, name)

    def mk_case_label(
            self,
            expr: Optional[AST.ASTExpr],
            optlocationid: Optional[int]=None) -> AST.ASTCaseLabel:
        locationid = self.get_locationid(optlocationid)
        if expr is None:
            # create an (uninitialized) temporary variable
            expr = self.mk_tmp_lval_expression()
        return AST.ASTCaseLabel(locationid, expr)

    def mk_case_range_label(
            self,
            lowexpr: AST.ASTExpr,
            highexpr: AST.ASTExpr,
            optlocationid: Optional[int]=None) -> AST.ASTCaseRangeLabel:
        locationid = self.get_locationid(optlocationid)
        return AST.ASTCaseRangeLabel(locationid, lowexpr, highexpr)

    def mk_default_label(
            self, optlocationid: Optional[int]=None) -> AST.ASTDefaultLabel:
        locationid = self.get_locationid(optlocationid)
        return AST.ASTDefaultLabel(locationid)

    """Instructions
    There are two types of instructions: an assignment and a call. An
    assignment consists of a lhs (lval) and a rhs (expression). A call consists
    of an optional lhs (lval) to which the return value from the call is
    assigned, an expression that is the target of the call (an lval expression
    of a variable of type function in case of a direct call, or any other
    expression in case of an indirect call), and a list of expressions that
    represent the arguments to the call (preferably in conformance with the
    arity of the function type, but this is not checked).

    Instructions are assigned a unique assembly cross reference, assembly_xref. 
    This cross reference can then be used to create a link with the instruction 
    address (via the span) if desired. If an assembly_xref was assigned earlier 
    (e.g., when constructing an ast from an existing ast json file) it can be 
    given as an optional argument.

    Construction methods provided:
    ------------------------------
    - mk_assign: creates an assignment from a lhs (lval) and rhs (expression)
    - mk_call: creates a call from an optional lhs (lval), a target (expression),
        and a list of arguments (expressions)

    - mk_var_assign: creates an assignment from a variable name and rhs
        (expression); an lval with the given name is created (as described
        below under Variables)
    - mk_var_var_assign: creates an assignment from one variable name to another
        variable name; an lval and lval-expression for the two variables is
        created (as described below under Variables)

    - mk_var_call: creates a call instruction with a variable name as lhs argument
    - mk_tgt_call: creates a call instruction with a function name as tgt expression

    - mk_default_call: creates a call instruction with only a function name and
         arguments, and optionally a type for the function name; this method tries
         to determine if the function has a return value (i.e., does not return
         void). If so it will create a tmp variable with a description that
         indicates this variable holds a return value from the named function,
         if the function has void return type, the lval is set to None.

    Note: if function prototypes are available before creating call instructions
      it is preferable that they be entered in the symbol table up front.
    """

    def mk_assign(
            self,
            lval: AST.ASTLval,
            rhs: AST.ASTExpr,
            optinstrid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            low_level_instrids: List[int] = []) -> AST.ASTAssign:
        instrid = self.get_instrid(optinstrid)
        locationid = self.get_locationid(optlocationid)
        self.addto_instruction_mapping(instrid, low_level_instrids)
        return AST.ASTAssign(instrid, locationid, lval, rhs)

    def mk_var_assign(
            self,
            vname: str,
            rhs: AST.ASTExpr,
            optinstrid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            low_level_instrids: List[int] = []) -> AST.ASTAssign:
        lval = self.mk_named_lval(vname)
        return self.mk_assign(
            lval,
            rhs,
            optinstrid=optinstrid,
            optlocationid=optlocationid,
            low_level_instrids=low_level_instrids)

    def mk_var_var_assign(
            self,
            vname: str,
            rhsname: str,
            optinstrid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            low_level_instrids: List[int] = []) -> AST.ASTAssign:
        rhs = self.mk_named_lval_expression(vname)
        return self.mk_var_assign(
            vname,
            rhs,
            optinstrid,
            optlocationid,
            low_level_instrids=low_level_instrids)

    def mk_call(
            self,
            lval: Optional[AST.ASTLval],
            tgt: AST.ASTExpr,
            args: List[AST.ASTExpr],
            optinstrid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            low_level_instrids: List[int] = []) -> AST.ASTCall:
        instrid = self.get_instrid(optinstrid)
        locationid = self.get_locationid(optlocationid)
        self.addto_instruction_mapping(instrid, low_level_instrids)
        return AST.ASTCall(instrid, locationid, lval, tgt, args)

    def mk_var_call(
            self,
            vname: str,
            tgt: AST.ASTExpr,
            args: List[AST.ASTExpr],
            optinstrid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            low_level_instrids: List[int] = []) -> AST.ASTCall:
        lval = self.mk_named_lval(vname)
        return self.mk_call(
            lval,
            tgt,
            args,
            optinstrid=optinstrid,
            optlocationid=optlocationid,
            low_level_instrids=low_level_instrids)

    def mk_tgt_call(
            self,
            lval: Optional[AST.ASTLval],
            tgtname: str,
            args: List[AST.ASTExpr],
            optinstrid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            low_level_instrids: List[int] = []) -> AST.ASTCall:
        tgtexpr = self.mk_named_lval_expression(tgtname)
        return self.mk_call(
            lval,
            tgtexpr,
            args,
            optinstrid=optinstrid,
            optlocationid=optlocationid,
            low_level_instrids=low_level_instrids)

    def mk_default_call(
            self,
            tgtvname: str,
            args: List[AST.ASTExpr],
            tgtvtype: Optional[AST.ASTTyp] = None,
            optinstrid: Optional[int] = None,
            optlocationid: Optional[int] = None,
            low_level_instrids: List[int] = []) -> AST.ASTCall:
        tgtvinfo = self.mk_vinfo(tgtvname, vtype=tgtvtype)
        lval: Optional[AST.ASTLval] = None
        if (
                tgtvinfo.vtype is not None
                and tgtvinfo.vtype.is_function):
            tgttyp = cast(AST.ASTTypFun, tgtvinfo.vtype)
            if tgttyp.is_void:
                lval = None
            else:
                lval = self.mk_tmp_lval(vdescr="return value from " + tgtvname)
        tgtexpr = self.mk_vinfo_lval_expression(tgtvinfo)
        return self.mk_call(
            lval,
            tgtexpr,
            args,
            optinstrid=optinstrid,
            optlocationid=optlocationid,
            low_level_instrids=low_level_instrids)

    """Variables

    Variables have a name. For named variables it is the user's responsibility
    to ensure that distinct variables (i.e. distinct storage locations) have
    distinct names (within a function) and that distinct global variables have
    distinct names (across all functions). Local variables in different\
    functions may have the same name (functions have different name spaces).

    The basic data structure for a variable is the ASTVarInfo, which holds the
    name, type (optional), the parameter index (zero-based) if the variable is
    a formal parameter to a function, the global address (optional) if the
    address is known, and an optional description of what the variable holds.
    The varinfo is stored in the local or global symbol table on first creation.

    The first creation of the varinfo determines the associate data. Once a
    variable exists (either in the global symbol or local symbol table)
    subsequent calls to create a variable with the same name (in the same name
    space result in retrieval of the existing varinfo rather than creating a
    new one, thereby ignoring the associate data provided.

    Only one instance exists of the ASTVarInfo data structure, held in the
    symboltable for each name. Multiple instances of related ASTVariable,
    ASTLval, and ASTLvalExpr may exist within the abstract syntax tree structure
    (these will all be collapsed into one by the serializer).

    Temporary variables are automatically given unique names.

    Construction methods provided:
    ------------------------------
    - mk_vinfo : creates/returns a varinfo data structure from the symboltable
        a vinfo is considered global if (1) it has a global address, or (2) its
        type is a function type.
        A vinfo can be forced global by giving it a global address of 0, if the
        actual address is not known.

    - mk_vinfo_variable: creates/returns a variable from a vinfo

    - mk_lval: creates/returns an lval from an lhost and an offset

    - mk_vinfo_lval: creates/returns an lval (lhs) (with optional offset) from
         a vinfo
    - mk_vinfo_lval_expression: creates/returns an lval-expression (rhs) (with
         optional offset) from a vinfo

    - mk_named_variable: creates a variable with the given a name (and will
         implicitly create a varinfo, if necessary)
    - mk_named_lval: creates an lval (lhs) (with optional offset) with the given
         name
    - mk_named_lval_expression: creates an lval expression (rhs) (with optional
         offset) with the given name

    - mk_tmp_variable: creates a new varinfo/variable with a unique name
    - mk_tmp_lval: creates a new varinfo/lval (lhs) with a unique name
    - mk_tmp_lval_expression: creates new varinfo/lval-expression (rhs) with a
         unique name
    """

    def mk_vinfo(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> AST.ASTVarInfo:
        if (
                (globaladdress is not None)
                or (vtype and vtype.is_function)):
            vinfo = self.symboltable.add_global_symbol(
                vname,
                vtype=vtype,
                globaladdress=globaladdress,
                vdescr=vdescr)
        else:
            vinfo = self.symboltable.add_symbol(
                vname,
                vtype=vtype,
                parameter=parameter,
                vdescr=vdescr)
        return vinfo

    def mk_vinfo_variable(self, vinfo: AST.ASTVarInfo) -> AST.ASTVariable:
        return AST.ASTVariable(vinfo)

    def mk_lval(
            self,
            lhost: AST.ASTLHost,
            offset: AST.ASTOffset,
            optlvalid: Optional[int] = None,
            storage: Optional[ASTStorage] = None) -> AST.ASTLval:
        lvalid = self.get_lvalid(optlvalid)
        if storage is not None:
            self.storage[lvalid] = storage
        return AST.ASTLval(lvalid, lhost, offset)

    def mk_vinfo_lval(
            self,
            vinfo: AST.ASTVarInfo,
            offset: AST.ASTOffset = nooffset,
            optlvalid: Optional[int] = None,
            storage: Optional[ASTStorage] = None) -> AST.ASTLval:
        var = self.mk_vinfo_variable(vinfo)
        return self.mk_lval(
            var,
            offset,
            optlvalid=optlvalid,
            storage=storage)

    def mk_vinfo_lval_expression(
            self,
            vinfo: AST.ASTVarInfo,
            offset: AST.ASTOffset = nooffset,
            optlvalid: Optional[int] = None,
            optexprid: Optional[int] = None,
            storage: Optional[ASTStorage] = None) -> AST.ASTLvalExpr:
        lval = self.mk_vinfo_lval(
            vinfo,
            offset,
            optlvalid=optlvalid,
            storage=storage)
        exprid = self.get_exprid(optexprid)
        return AST.ASTLvalExpr(exprid, lval)

    def mk_named_variable(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None) -> AST.ASTVariable:
        vinfo = self.mk_vinfo(
            vname,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr)
        return self.mk_vinfo_variable(vinfo)

    def mk_named_lval(
            self,
            vname: str,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            globaladdress: Optional[int] = None,
            vdescr: Optional[str] = None,
            offset: AST.ASTOffset = nooffset,
            optlvalid: Optional[int] = None,
            storage: Optional[ASTStorage] = None) -> AST.ASTLval:
        var = self.mk_named_variable(
            vname,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr)
        return self.mk_lval(
            var,
            offset,
            optlvalid=optlvalid,
            storage=storage)

    def mk_register_variable_lval(
            self,
            name: str,
            registername: Optional[str] = None,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            vdescr: Optional[str] = None,
            optlvalid: Optional[int] = None) -> AST.ASTLval:
        if registername is None:
            registername = name
        storage = self.storageconstructor.mk_register_storage(registername)
        return self.mk_named_lval(
            name,
            vtype=vtype,
            parameter=parameter,
            vdescr=vdescr,
            storage=storage,
            optlvalid=optlvalid)

    def mk_flag_variable_lval(
            self,
            name: str,
            flagname: Optional[str] = None,
            vdescr: Optional[str] = None,
            optlvalid: Optional[int] = None) -> AST.ASTLval:
        if flagname is None:
            flagname = name
        storage = self.storageconstructor.mk_flag_storage(flagname)
        return self.mk_named_lval(
            name,
            storage=storage,
            optlvalid=optlvalid)

    def mk_flag_variable_lval_expression(
            self,
            name: str,
            flagname: Optional[str] = None,
            vdescr: Optional[str] = None,
            optlvalid: Optional[int] = None,
            optexprid: Optional[int] = None) -> AST.ASTLvalExpr:
        lval = self.mk_flag_variable_lval(
            name, flagname=flagname, vdescr=vdescr, optlvalid=optlvalid)
        exprid = self.get_exprid(optexprid)
        return AST.ASTLvalExpr(exprid, lval)

    def mk_stack_variable_lval(
            self,
            name: str,
            offset: int,
            vtype: Optional[AST.ASTTyp] = None,
            parameter: Optional[int] = None,
            vdescr: Optional[str] = None,
            size: Optional[int] = None,
            optlvalid: Optional[int] = None) -> AST.ASTLval:
        storage = self.storageconstructor.mk_stack_storage(offset, size)
        return self.mk_named_lval(
            name,
            vtype=vtype,
            parameter=parameter,
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
            optlvalid: Optional[int] = None,
            optexprid: Optional[int] = None,
            storage: Optional[ASTStorage] = None) -> AST.ASTLvalExpr:
        lval = self.mk_named_lval(
            vname,
            vtype=vtype,
            parameter=parameter,
            globaladdress=globaladdress,
            vdescr=vdescr,
            offset=offset,
            storage=storage,
            optlvalid=optlvalid)
        exprid = self.get_exprid(optexprid)
        return AST.ASTLvalExpr(exprid, lval)

    def new_tmp_name(self) -> str:
        tmpid = self._tmpcounter
        self._tmpcounter += 1
        return "__asttmp_" + str(tmpid) + "__"

    def mk_tmp_variable(
            self,
            vtype: Optional[AST.ASTTyp] = None,
            vdescr: Optional[str] = None) -> AST.ASTVariable:
        vname = self.new_tmp_name()
        return self.mk_named_variable(vname, vtype=vtype, vdescr=vdescr)

    def mk_tmp_lval(
            self,
            vtype: Optional[AST.ASTTyp] = None,
            vdescr: Optional[str] = None) -> AST.ASTLval:
        vname = self.new_tmp_name()
        return self.mk_named_lval(vname, vtype=vtype, vdescr=vdescr)

    def mk_tmp_lval_expression(
            self,
            vtype: Optional[AST.ASTTyp] = None,
            vdescr: Optional[str] = None) -> AST.ASTLvalExpr:
        vname = self.new_tmp_name()
        return self.mk_named_lval_expression(
            vname, vtype=vtype, vdescr=vdescr)

    """Storage

    Lvalues are (mostly) associated with physical locations in the architecture,
    such as registers, stack locations, heap locations, and global locations.
    From a function point-of-view four distinct types of storage are recognized:
    - registers: this includes the standard CPU registers, but may also include
      the processor status word, or individual flags in the processor status
      words. Registers are identified by their name.
    - stack locations: these are memory locations identified by a fixed offset
      (specified in bytes) from the stack pointer value at function entry.
      Offsets can be positive (parent stack frame or argument slots) or negative
      (local stack frame) or zero (return address on x86, local stack frame on ARM).
    - base locations: these are memory locations identified by a fixed offset
      (specified in bytes) from a base pointer, specified by an expression
      (represented by a string) that is guaranteed to be constant throughout the
      lifetime of the function, e.g., a pointer argument to the function.
    - global locations: these are memory locations identified by their virtual
      address (represented as a hex string).

    Storage locations may optionally have a size (specified in bits), or can be
    set to be the default word size of the architecture (e.g., 32 bits for
    ARM32/Thumb2 or x86).

    Construction methods are provided for each the four types.

    """

    def mk_register_storage(self, name: str) -> ASTRegisterStorage:
        return self.storageconstructor.mk_register_storage(name)

    def mk_stack_storage(
            self, offset: int, size: Optional[int]) -> ASTStackStorage:
        return self.storageconstructor.mk_stack_storage(offset, size)

    def mk_base_storage(
            self, base: str, offset: int, size: Optional[int]) -> ASTBaseStorage:
        return self.storageconstructor.mk_base_storage(base, offset, size)

    def mk_global_storage(
            self, address: str, size: Optional[int]) -> ASTGlobalStorage:
        return self.storageconstructor.mk_global_storage(address, size)


    """Offsets

    The default offset in lval creation is NoOffset, provided as constant
    value nooffset.

    The other two options are a field offset (to access struct fields) and
    an index offset (to access array elements).

    To create a field offset, create a the compinfo data structure first to
    obtain the compkey value of the struct. The type of the field can then
    be obtained from the compinfo data structure.

    An index offset can be created either with an integer or with an expression;
    note that by C semantics the index offset must be scaled by the size of
    the array element.

    The field offset and index offset can have sub-offsets. Default for these
    sub-offsets is nooffset.

    Construction methods provided:
    - mk_field_offset: create a field offset from the name of the field and
         the key of corresponding struct (compinfo)

    - mk_scalar_index_offset: create an index offset from an integer value
    - mk_expr_index_offset: create an index offset from an expression
    """

    def mk_field_offset(
            self,
            fieldname: str,
            compkey: int,
            offset: AST.ASTOffset = nooffset) -> AST.ASTFieldOffset:
        return AST.ASTFieldOffset(fieldname, compkey, offset)

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

    """Other lvals and expressions

    Lvals (lhs) can also be made from dereferenced pointer expressions
    (memory reference, or memref expressions).

    Several kinds of other expressions can be created.

    Construction methods provided:
    - mk_lval_expression: create an lval expression for a generic lhost and offset

    - mk_memref: create an lhs base value (lhost) from an expression
    - mk_memref_lval: create an lval (lhs) from a memref and an offset
    - mk_memref_expression: create an val expression (rhs) from a a memref
        and an offset

    - mk_integer_constant: create an integer constant from an integer
    - mk_string_constant: create a string constant from a string and the
        expression that produced the string address, and the string address
        itself (in hex) (to ensure proper identification)

    - mk_unary_expression: create an expression that applies a unary operator
        to an expression
    - mk_binary_expression: create an expression that applies a binary operator
        to two expressions
    - mk_question_expression: create an expression that applies the question
        operator to three expressions
    - mk_address_of_expression: create an expression that applies the address-of
        operator an lval
    - mk_cast_expression: create an expression that casts another expression to
        a given type

    Some special-purpose expression
    - mk_plus_expression: create a sum binary expression
    - mk_minus_expression: create a difference binary expression
    - mk_multiplication_expression: create a product binary expression

    - mk_negation_expression: create a negation unary expression
    - mk_bitwise_not_expression: create a bitwise not unary expression
    - mk_logical_not_expression: create a logical not unary expression

    """

    def mk_lval_expression(
            self,
            lval: AST.ASTLval,
            optexprid: Optional[int] = None) -> AST.ASTLvalExpr:
        exprid = self.get_exprid(optexprid)
        return AST.ASTLvalExpr(exprid, lval)

    def mk_memref(self, memexp: AST.ASTExpr) -> AST.ASTMemRef:
        return AST.ASTMemRef(memexp)

    def mk_memref_lval(
            self,
            memexp: AST.ASTExpr,
            offset: AST.ASTOffset = nooffset,
            optlvalid: Optional[int] = None) -> AST.ASTLval:
        memref = self.mk_memref(memexp)
        return self.mk_lval(memref, offset, optlvalid=optlvalid)

    def mk_memref_expression(
            self,
            memexp: AST.ASTExpr,
            offset: AST.ASTOffset = nooffset,
            optexprid: Optional[int] = None) -> AST.ASTExpr:
        memreflval = self.mk_memref_lval(memexp, offset)
        return self.mk_lval_expression(memreflval, optexprid=optexprid)

    def mk_integer_constant(
            self,
            cvalue: int,
            optexprid: Optional[int] = None) -> AST.ASTIntegerConstant:
        exprid = -1 if optexprid is None else optexprid
        return AST.ASTIntegerConstant(exprid, cvalue)

    def mk_string_constant(
            self,
            expr: Optional[AST.ASTExpr],
            cstr: str,
            string_address: Optional[str] = None,
            optexprid: Optional[int] = None) -> AST.ASTStringConstant:
        exprid = self.get_exprid(optexprid)
        return AST.ASTStringConstant(exprid, expr, cstr, string_address)

    def mk_address_of_expression(
            self,
            lval: AST.ASTLval,
            optexprid: Optional[int] = None) -> AST.ASTAddressOf:
        exprid = self.get_exprid(optexprid)
        return AST.ASTAddressOf(exprid, lval)

    def mk_binary_expression(
            self,
            op: str,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr,
            optexprid: Optional[int] = None) -> AST.ASTExpr:
        exprid = self.get_exprid(optexprid)
        return AST.ASTBinaryOp(exprid, op, exp1, exp2)

    def mk_plus_expression(
            self, exp1: AST.ASTExpr, exp2: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_binary_expression("plus", exp1, exp2)

    def mk_minus_expression(
            self, exp1: AST.ASTExpr, exp2: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_binary_expression("minus", exp1, exp2)

    def mk_multiplication_expression(
            self, exp1: AST.ASTExpr, exp2: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_binary_expression("mult", exp1, exp2)

    def mk_question_expression(
            self,
            exp1: AST.ASTExpr,
            exp2: AST.ASTExpr,
            exp3: AST.ASTExpr,
            optexprid: Optional[int] = None) -> AST.ASTExpr:
        exprid = self.get_exprid(optexprid)
        return AST.ASTQuestion(exprid, exp1, exp2, exp3)

    def mk_unary_expression(
            self,
            op: str,
            exp: AST.ASTExpr,
            optexprid: Optional[int] = None) -> AST.ASTExpr:
        exprid = self.get_exprid(optexprid)
        return AST.ASTUnaryOp(exprid, op, exp)

    def mk_negation_expression(self, exp: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_unary_expression("neg", exp)

    def mk_bitwise_not_expression(self, exp: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_unary_expression("bnot", exp)

    def mk_logical_not_expression(self, exp: AST.ASTExpr) -> AST.ASTExpr:
        return self.mk_unary_expression("lnot", exp)

    def mk_cast_expression(
            self,
            tgttyp: AST.ASTTyp,
            exp: AST.ASTExpr,
            optexprid: Optional[int] = None) -> AST.ASTExpr:
        exprid = self.get_exprid(optexprid)
        return AST.ASTCastExpr(exprid, tgttyp, exp)


    """Types

    Integer and Float types
    ------------------------
    Integer and Float types can be created directly with their ikind/fkind
    specifier with:

    - mk_integer_ikind_type()
    - mk_float_fkind_type()

    or can be obtained as properties for the individual ikind/fkind specifiers:

    - char_type
    - signed_char_type
    - unsigned_char_type
    - bool_type
    - int_type
    - unsigned_int_type
    - short_type
    - unsigned_short_type
    - long_type
    - unsigned_long_type
    - long_long_type
    - unsigned_long_long_type

    - float_type
    - double_type
    - long_double_type

    Creators of other types:

    - mk_pointer_type
        specify the type of the data pointed at

    - mk_array_type
        specify the element type and, optionally, an expression for the 
        number of elements
    - mk_int_sized_array_type
        specify the element type and a numerical value for the number of
        elements

    - mk_function_type
        specify the return type and the arguments (as a ASTFunArgs)
    - mk_function_with_arguments_type
        specify the return type and the arguments (as a list of name, type
        pairs)

    - mk_typedef
        associate a name with a type

    Struct types
    ------------
    Struct types are specified by the compinfo data structure. Compinfo data
    structures are uniquely identified by an integer key (ckey) to be provided
    by the user. When a new compinfo is created it is registered in the global
    symbol table; subsequent attempts to create a compinfo with the same ckey 
    value will just return the one created earlier. It is also possible to
    pre-populate the global symbol table with compinfo data structures, if they
    are available up front. Struct types are thus global and shared by different
    functions. Field offsets also include the ckey of the compinfo that they
    belong to.

    Related methods:

    - mk_comp_info
        specify the fields as FieldInfos
    - mk_compinfo_with_fields
        specify the fields as a list of (name, type) tuples

    - mk_fieldinfo
        specify name and type for a single field, with the key of the
        compinfo to which it belongs; optionally the byte offset at which
        the field is located within the struct can be specified as well

    - mk_comp_type
        specify a compinfo to get a struct type
    - mk_comp_type_by_key
        specify a compinfo ckey value and name to get a struct type

    - mk_named_type
        specify a type definition with a name and type

    """

    def mk_integer_ikind_type(self, ikind: str) -> AST.ASTTypInt:
        return AST.ASTTypInt(ikind)

    @property
    def char_type(self) -> AST.ASTTypInt:
        return self._char_type

    @property
    def signed_char_type(self) -> AST.ASTTypInt:
        return self._signed_char_type

    @property
    def unsigned_char_type(self) -> AST.ASTTypInt:
        return self._unsigned_char_type

    @property
    def bool_type(self) -> AST.ASTTypInt:
        return self._bool_type

    @property
    def int_type(self) -> AST.ASTTypInt:
        return self._int_type

    @property
    def unsigned_int_type(self) -> AST.ASTTypInt:
        return self._unsigned_int_type

    @property
    def short_type(self) -> AST.ASTTypInt:
        return self._short_type

    @property
    def unsigned_short_type(self) -> AST.ASTTypInt:
        return self._unsigned_short_type

    @property
    def long_type(self) -> AST.ASTTypInt:
        return self._long_type

    @property
    def unsigned_long_type(self) -> AST.ASTTypInt:
        return self._unsigned_long_type

    @property
    def long_long_type(self) -> AST.ASTTypInt:
        return self._long_long_type

    @property
    def unsigned_long_long_type(self) -> AST.ASTTypInt:
        return self._unsigned_long_type

    def mk_float_fkind_type(self, fkind: str) -> AST.ASTTypFloat:
        return AST.ASTTypFloat(fkind)

    @property
    def float_type(self) -> AST.ASTTypFloat:
        return self._float_type

    @property
    def double_type(self) -> AST.ASTTypFloat:
        return self._double_type

    @property
    def long_double_type(self) -> AST.ASTTypFloat:
        return self._long_double_type

    def mk_pointer_type(self, tgttype: AST.ASTTyp) -> AST.ASTTypPtr:
        return AST.ASTTypPtr(tgttype)

    def mk_array_type(
            self,
            tgttype: AST.ASTTyp,
            size: Optional[AST.ASTExpr]) -> AST.ASTTyp:
        return AST.ASTTypArray(tgttype, size)

    def mk_int_sized_array_type(
            self,
            tgttype: AST.ASTTyp,
            nelements: int) -> AST.ASTTyp:
        size = self.mk_integer_constant(nelements)
        return self.mk_array_type(tgttype, size)

    def mk_function_type_argument(
            self, argname: str, argtype: AST.ASTTyp) -> AST.ASTFunArg:
        return AST.ASTFunArg(argname, argtype)

    def mk_function_type_arguments(
            self, args: List[AST.ASTFunArg]) -> AST.ASTFunArgs:
        return AST.ASTFunArgs(args)

    def mk_function_type(
            self,
            returntype: AST.ASTTyp,
            arguments: Optional[AST.ASTFunArgs],
            varargs: bool = False) -> AST.ASTTypFun:
        return AST.ASTTypFun(returntype, arguments, varargs=varargs)

    def mk_function_with_arguments_type(
            self,
            returntype: AST.ASTTyp,
            arguments: List[Tuple[str, AST.ASTTyp]],
            varargs: bool = False) -> AST.ASTTypFun:
        funargs = AST.ASTFunArgs(
            [AST.ASTFunArg(name, typ) for (name, typ) in arguments])
        return AST.ASTTypFun(returntype, funargs, varargs=varargs)

    def mk_typedef(self, name: str, typ: AST.ASTTyp) -> AST.ASTTypNamed:
        return AST.ASTTypNamed(name, typ)

    def mk_compinfo(
            self,
            cname: str,
            ckey: int,
            fieldinfos: List[AST.ASTFieldInfo],
            is_union: bool = False) -> AST.ASTCompInfo:
        if ckey in self.compinfos:
            return self.compinfos[ckey]
        else:
            # check that all fields share the same ckey value
            if any(ckey != finfo.compkey for finfo in fieldinfos):
                raise Exception(
                    "Field infos do not all share the same ckey value")

            cinfo = AST.ASTCompInfo(cname, ckey, fieldinfos, is_union=is_union)
            self.add_compinfo(cinfo)
            return cinfo

    def mk_compinfo_with_fields(
            self,
            cname: str,
            ckey: int,
            fields: List[Tuple[str, AST.ASTTyp]],
            is_union: bool = False) -> AST.ASTCompInfo:
        known_cinfo = self.get_comp_info(ckey)
        if known_cinfo is not None:
            return known_cinfo
        else:
            fieldinfos: List[AST.ASTFieldInfo] = []
            for (fname, ftyp) in fields:
                fieldinfos.append(AST.ASTFieldInfo(fname, ftyp, ckey))
            return self.mk_compinfo(cname, ckey, fieldinfos, is_union=is_union)

    def mk_fieldinfo(
            self,
            fname: str,
            ftype: AST.ASTTyp,
            ckey: int,
            byteoffset: Optional[int] = None) -> AST.ASTFieldInfo:
        return AST.ASTFieldInfo(fname, ftype, ckey, byteoffset=byteoffset)

    def mk_comp_type(self, cinfo: AST.ASTCompInfo) -> AST.ASTTypComp:
        known_cinfo = self.get_comp_info(cinfo.compkey)
        if known_cinfo is not None:
            return AST.ASTTypComp(known_cinfo.compname, known_cinfo.compkey)
        else:
            self.add_compinfo(cinfo)
            return AST.ASTTypComp(cinfo.compname, cinfo.compkey)

    def mk_comp_type_by_key(self, ckey: int, cname: str) -> AST.ASTTypComp:
        return AST.ASTTypComp(cname, ckey)

    def get_comp_info(self, compkey: int) -> Optional[AST.ASTCompInfo]:
        """Returns the compound type associated with the passed key

        If the compkey is not known, None is returned.
        """
        return self.compinfos.get(compkey, None)
