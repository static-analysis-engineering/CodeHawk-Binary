# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022 Aarno Labs LLC
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
"""Simplified version of AST to check serialization."""

from typing import Any, cast, Dict, List, NewType, Optional, Tuple, Union

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree, nooffset, voidtype
import chb.ast.ASTNode as AST
from chb.ast.ASTSymbolTable import ASTLocalSymbolTable, ASTGlobalSymbolTable
from chb.ast.ASTReturnSequences import ASTReturnSequences
from chb.ast.ASTCodeFragments import ASTCodeFragments


ASTSpanRecord = NewType(
    "ASTSpanRecord", Dict[str, Union[int, List[Dict[str, Union[str, int]]]]])


class ASTDeserializer:

    def __init__(
            self,
            serialization: Dict[str, Any]) -> None:
        self._serialization = serialization
        self._globalsymboltable: ASTGlobalSymbolTable = ASTGlobalSymbolTable()
        self._annotations: Dict[int, List[str]] = {}
        self._initialize_global_symboltable()
        self._functions: Dict[str, Tuple[ASTLocalSymbolTable, AST.ASTStmt]] = {}
        self._reachingdefinitions: Dict[str, List[Tuple[str, List[str]]]] = {}
        self._lifted_functions: Dict[
            str, Tuple[ASTLocalSymbolTable, AST.ASTStmt]] = {}
        self._initialize_functions()
        self._initialize_lifted_functions()

    @property
    def serialization(self) -> Dict[str, Any]:
        return self._serialization

    @property
    def global_symboltable(self) -> ASTGlobalSymbolTable:
        return self._globalsymboltable

    @property
    def functions(self) -> Dict[str, Tuple[ASTLocalSymbolTable, AST.ASTStmt]]:
        return self._functions

    @property
    def lifted_functions(self) -> Dict[
            str, Tuple[ASTLocalSymbolTable, AST.ASTStmt]]:
        return self._lifted_functions

    @property
    def reaching_definitions(self) -> Dict[
            str, List[Tuple[str, List[str]]]]:
        return self._reachingdefinitions

    @property
    def annotations(self) -> Dict[int, List[str]]:
        return self._annotations

    def print_node_descendants(self, id: int) -> None:
        nodes: Dict[int, Dict[str, Any]] = {}
        for fdata in self.serialization["functions"]:
            for r in fdata["ast"]["nodes"]:
                nodes[r["id"]] = r

        def aux(p: int, level: int = 0) -> None:
            pnode = nodes[p]
            if pnode["tag"] == "binary-op":
                tag = "binary-op:" + pnode["op"] + ":" + str(pnode["exprid"])
            elif pnode["tag"] == "integer-constant":
                tag = "integer-constant:" + pnode["value"]
            elif pnode["tag"] == "varinfo":
                tag = "varinfo:" + pnode["name"]
            else:
                tag = pnode["tag"]
            print((" " * level) + str(pnode["id"]).rjust(5) + " " + tag)
            for c in pnode["args"]:
                if c >= 0:
                    aux(c, level + 2)

        print("\nDescendants of node: " + str(id))
        aux(id)

    def print_node_ancestors(self, id: int) -> None:
        parents: Dict[int, List[int]] = {}
        nodes: Dict[int, Dict[str, Any]] = {}
        for fdata in self.serialization["functions"]:
            for r in fdata["ast"]["nodes"]:
                nodes[r["id"]] = r
                args = r["args"]
                for a in args:
                    if a >= 0:
                        parents.setdefault(a, [])
                        parents[a].append(r["id"])

        def aux(c: int, level: int = 0, baselevel: int = 0) -> None:
            cnode = nodes[c]
            if cnode["tag"] == "binary-op":
                tag = "binary-op:" + cnode["op"] + ":" + str(cnode["exprid"])
            else:
                tag = cnode["tag"]
            prefix = (" " * baselevel) + "|" + (" " * (level - baselevel))
            print(prefix + str(cnode["id"]).rjust(5) + " " + tag)
            if c in parents:
                baselevel = level + 2 if len(parents[c]) > 1 else baselevel
                for p in parents[c]:
                    aux(p, level + 2, baselevel)

        print("\nAncestors of node: " + str(id))
        aux(id)

    def node_ancestors(self, nodeid: int) -> List[List[str]]:
        parents: Dict[int, List[int]] = {}
        nodes: Dict[int, Dict[str, Any]] = {}
        paths: List[List[str]] = []

        for fdata in self.serialization["functions"]:
            for r in fdata["ast"]["nodes"]:
                id = r["id"]
                nodes[id] = r
                args = r["args"]
                for a in args:
                    if a >= 0:
                        parents.setdefault(a, [])
                        parents[a].append(r["id"])

        def aux(c: int, prefix: List[str]) -> None:
            cnode = nodes[c]
            name = str(c) + ":" + cnode["tag"]
            if "exprid" in cnode:
                name += "(" + str(cnode["exprid"]) + ")"
            elif "instrid" in cnode:
                name += "(" + str(cnode["instrid"]) + ")"
            prefix.append(name)
            if c in parents:
                for p in parents[c]:
                    aux(p, prefix)
            else:
                paths.append(prefix[:])
            prefix.pop()

        aux(nodeid, [])
        return paths

    def check_expr_node_parentage(self) -> None:
        parents: Dict[int, List[int]] = {}
        nodes: Dict[int, Dict[str, Any]] = {}
        freq: Dict[str, Tuple[int, int]] = {}
        for fdata in self.serialization["functions"]:
            for r in fdata["ast"]["nodes"]:
                id = r["id"]
                nodes[id] = r
                args = r["args"]
                for a in args:
                    parents.setdefault(a, [])
                    parents[a].append(id)
        for (child, pars) in sorted(parents.items()):
            if child >= 0 and len(pars) > 1:
                tag = nodes[child]["tag"]
                freq.setdefault(tag, (0, 0))
                freq[tag] = (freq[tag][0] + 1, freq[tag][1] + len(pars))
                if "exprid" in nodes[child] and "value" not in nodes[child]:
                    self.print_node_descendants(child)
                    self.print_node_ancestors(child)
                    self.node_ancestors(child)

        print("\nNode sharing statistics")
        print("---------------------------------------------------------------")
        for tag in sorted(freq):
            print(
                tag.ljust(20)
                + str(freq[tag][0]).rjust(8)
                + str(freq[tag][1]).rjust(8))
        print("---------------------------------------------------------------")

    def _initialize_global_symboltable(self) -> None:
        globaltable = self.serialization["global-symbol-table"]
        astree = AbstractSyntaxTree(
            "none", "none", ASTLocalSymbolTable(self.global_symboltable))
        self.mk_ast_nodes(astree, globaltable)

    def _initialize_functions(self) -> None:
        for fdata in self.serialization["functions"]:
            self._initialize_function(fdata)

    def _initialize_function_prototype(
            self,
            index: int,
            astree: AbstractSyntaxTree,
            nodes: Dict[int, AST.ASTNode]) -> None:
        if index >= 0:
            if index in nodes:
                fprototype = cast(AST.ASTVarInfo, nodes[index])
                astree.set_function_prototype(fprototype)
            else:
                raise Exception(
                    "Index for prototype "
                    + str(index)
                    + " not found in nodes deserialized")

    def _initialize_function(self, fdata: Dict[str, Any]) -> None:
        fname = fdata["name"]
        faddr = fdata["va"]
        localsymboltable = ASTLocalSymbolTable(self.global_symboltable)
        astree = AbstractSyntaxTree(faddr, fname, localsymboltable)
        nodes = self.mk_ast_nodes(astree, fdata["ast"]["nodes"])
        if "prototype" in fdata:
            fprototypeix = fdata["prototype"]
            self._initialize_function_prototype(fprototypeix, astree, nodes)
        astnode = cast(AST.ASTStmt, nodes[int(fdata["ast"]["ast-startnodes"][-1])])
        self._functions[faddr] = (localsymboltable, astnode)

    def _initialize_lifted_functions(self) -> None:
        for fdata in self.serialization["functions"]:
            self._initialize_lifted_function(fdata)
            self._initialize_provenance(fdata)

    def _initialize_lifted_function(self, fdata: Dict[str, Any]) -> None:
        fname = fdata["name"]
        faddr = fdata["va"]
        localsymboltable = ASTLocalSymbolTable(self.global_symboltable)
        astree = AbstractSyntaxTree(faddr, fname, localsymboltable)
        nodes = self.mk_ast_nodes(astree, fdata["ast"]["nodes"])
        if "prototype" in fdata:
            fprototypeix = fdata["prototype"]
            self._initialize_function_prototype(fprototypeix, astree, nodes)
        astnode = cast(AST.ASTStmt, nodes[int(fdata["ast"]["ast-startnodes"][0])])
        self._lifted_functions[faddr] = (localsymboltable, astnode)

    def _initialize_provenance(self, fdata: Dict[str, Any]) -> None:
        fname = fdata["name"]
        faddr = fdata["va"]
        localsymboltable = ASTLocalSymbolTable(self.global_symboltable)
        astree = AbstractSyntaxTree(faddr, fname, localsymboltable)
        nodes = self.mk_ast_nodes(astree, fdata["ast"]["nodes"])
        prov = fdata["provenance"]
        spans = fdata["spans"]
        rds = prov["reaching-definitions"]

        def find_expr_by_id(nodes: Dict[int, AST.ASTNode], exprid: int) -> AST.ASTNode:
            for node in fdata["ast"]["nodes"]:
                if "exprid" in node and int(node["exprid"]) == exprid:
                    return nodes[int(node["id"])]
            else:
                raise Exception(
                    "Exprid: "
                    + str(exprid)
                    + " not found")

        def find_instr_by_id(nodes: Dict[int, AST.ASTNode], instrid: int) -> AST.ASTNode:
            for node in fdata["ast"]["nodes"]:
                if "instrid" in node and int(node["instrid"]) == instrid:
                    return nodes[int(node["id"])]
            else:
                raise Exception(
                    "Instrid: "
                    + str(instrid)
                    + " not found")

        def find_instr_address_by_locationid(locationid: int) -> str:
            for node in fdata["spans"]:
                if "locationid" in node and int(node["locationid"]) == locationid:
                    return node["spans"][0]["base_va"]
            else:
                raise Exception(
                    "No span found for locationid: " + str(locationid))

        def find_expr_address_by_exprid(exprid: int) -> str:
            for node in fdata["spans"]:
                if "exprid" in node and int(node["exprid"]) == exprid:
                    return node["spans"][0]["base_va"]
            else:
                raise Exception(
                    "No span found for exprid: " + str(exprid))

        print("\nReaching definitions")
        result: List[Tuple[str, List[str]]] = []
        for (exprid, instrids) in rds.items():
            exprnode = find_expr_by_id(nodes, exprid)
            for instrid in instrids:
                p_instrs: List[str] = []
                instrnode = cast(AST.ASTInstruction, find_instr_by_id(nodes, instrid))
                try:
                    address = find_instr_address_by_locationid(instrnode.locationid)
                except Exception as e:
                    p_instrs.append(str(instrnode) + ": " + str(e))
                    address = "?"
                p_instrs.append(
                    "  <" + str(instrid) + "> " + str(instrnode) + " (" + address + ")")
            result.append((str(exprnode), p_instrs))
        self._reachingdefinitions[faddr] = result

    def mk_ast_nodes(
            self,
            astree: AbstractSyntaxTree,
            recordlist: List[Dict[str, Any]]) -> Dict[int, AST.ASTNode]:

        records: Dict[int, Dict[str, Any]] = {}
        for r in recordlist:
            if "id" not in r:
                print(str(r))
            records[r["id"]] = r

        nodes: Dict[int, AST.ASTNode] = {}

        def mk_node(r: Dict[str, Any]) -> AST.ASTNode:
            id = r["id"]
            if id in nodes:
                return nodes[id]

            def arg(ix: int) -> Dict[str, Any]:
                return records[r["args"][ix]]

            tag = r["tag"]
            if tag == "void":
                nodes[id] = voidtype

            elif tag == "int":
                nodes[id] = astree.mk_integer_ikind_type(r["ikind"])

            elif tag == "float":
                nodes[id] = astree.mk_float_fkind_type(r["fkind"])

            elif tag == "ptr":
                tgttyp = cast(AST.ASTTyp, mk_node(arg(0)))
                nodes[id] = astree.mk_pointer_type(tgttyp)

            elif tag == "array":
                tgttyp = cast(AST.ASTTyp, mk_node(arg(0)))
                if r["args"][1] == -1:
                    sizexpr: Optional[AST.ASTExpr] = None
                else:
                    sizexpr = cast(AST.ASTExpr, mk_node(arg(1)))
                nodes[id] = astree.mk_array_type(tgttyp, sizexpr)

            elif tag == "comptyp":
                ckey = r["compkey"]
                name = r["name"]
                nodes[id] = astree.mk_comp_type_by_key(ckey, name)

            elif tag == "enumtyp":
                enumname = r["name"]
                nodes[id] = astree.mk_enum_type_by_name(enumname)

            elif tag == "typdef":
                name = r["name"]
                typ = cast(AST.ASTTyp, mk_node(arg(0)))
                nodes[id] = astree.mk_typedef(name, typ)

            elif tag == "funarg":
                name = r["name"]
                typ = cast(AST.ASTTyp, mk_node(arg(0)))
                nodes[id] = astree.mk_function_type_argument(name, typ)

            elif tag == "funargs":
                funargs: List[AST.ASTFunArg] = [
                    cast(AST.ASTFunArg, mk_node(records[i])) for i in r["args"]]
                nodes[id] = astree.mk_function_type_arguments(funargs)

            elif tag == "funtype":
                returntype = cast(AST.ASTTyp, mk_node(arg(0)))
                xfunargs = r["args"][1]
                if xfunargs == -1:
                    ffunargs: Optional[AST.ASTFunArgs] = None
                else:
                    ffunargs = cast(AST.ASTFunArgs, mk_node(records[xfunargs]))
                varargs = r["varargs"] == "yes"
                nodes[id] = astree.mk_function_type(
                    returntype, ffunargs, varargs=varargs)

            elif tag == "fieldinfo":
                ftype = cast(AST.ASTTyp, mk_node(arg(0)))
                fname = r["name"]
                ckey = int(r["compkey"])
                byteoffset = int(r["byte-offset"]) if "byte-offset" in r else None
                nodes[id] = astree.mk_fieldinfo(
                    fname, ftype, ckey, byteoffset=byteoffset)

            elif tag == "compinfo":
                finfos = [
                    cast(AST.ASTFieldInfo, mk_node(records[i]))
                    for i in r["args"]]
                name = r["name"]
                compkey = int(r["compkey"])
                is_union = r["union"] == "yes"
                nodes[id] = astree.mk_compinfo(
                    name, compkey, finfos, is_union=is_union)

            elif tag == "enumitem":
                itemname = r["name"]
                itemvalue = cast(AST.ASTExpr, mk_node(arg(0)))
                nodes[id] = astree.mk_enum_item(itemname, itemvalue)

            elif tag == "enuminfo":
                enumitems = [
                    cast(AST.ASTEnumItem, mk_node(records[i]))
                    for i in r["args"]]
                enumname = r["name"]
                enumkind = r["ekind"]
                nodes[id] = astree.mk_enuminfo(enumname, enumkind, enumitems)

            elif tag == "varinfo":
                name = r["name"]
                xtyp = r["args"][0]
                xpar = r["parameter"]
                xgaddr = r["globaladdress"]
                if xtyp == -1:
                    vtype: Optional[AST.ASTTyp] = None
                else:
                    vtype = cast(AST.ASTTyp, mk_node(arg(0)))
                if xpar == -1:
                    parindex: Optional[int] = None
                else:
                    parindex = xpar
                if xgaddr == -1:
                    gaddr: Optional[int] = None
                else:
                    gaddr = xgaddr
                if "descr" in r:
                    vdescr: Optional[str] = r["descr"]
                else:
                    vdescr = None
                nodes[id] = astree.mk_vinfo(
                    name,
                    vtype=vtype,
                    parameter=parindex,
                    globaladdress=gaddr,
                    vdescr=vdescr)

            elif tag == "var":
                vinfo = cast(AST.ASTVarInfo, mk_node(arg(0)))
                nodes[id] = astree.mk_vinfo_variable(vinfo)

            elif tag == "memref":
                expr = cast(AST.ASTExpr, mk_node(arg(0)))
                nodes[id] = astree.mk_memref(expr)

            elif tag == "no-offset":
                nodes[id] = nooffset

            elif tag == "field-offset":
                fname = r["name"]
                compkey = r["compkey"]
                offset = cast(AST.ASTOffset, mk_node(arg(0)))
                nodes[id] = astree.mk_field_offset(fname, compkey, offset)

            elif tag == "index-offset":
                expr = cast(AST.ASTExpr, mk_node(arg(0)))
                offset = cast(AST.ASTOffset, mk_node(arg(1)))
                nodes[id] = astree.mk_expr_index_offset(expr, offset)

            elif tag == "lval":
                lvalid = r["lvalid"]
                host = cast(AST.ASTLHost, mk_node(arg(0)))
                offset = cast(AST.ASTOffset, mk_node(arg(1)))
                nodes[id] = astree.mk_lval(host, offset, optlvalid=lvalid)

            elif tag == "integer-constant":
                exprid = r["exprid"]
                cvalue = int(r["value"])
                nodes[id] = astree.mk_integer_constant(cvalue, optexprid=exprid)

            elif tag == "global-address":
                exprid = r["exprid"]
                cvalue = int(r["value"])
                address_expr = cast(AST.ASTExpr, mk_node(arg(0)))
                nodes[id] = astree.mk_global_address_constant(
                    cvalue, address_expr, optexprid=exprid)

            elif tag == "fp-constant":
                exprid = r["exprid"]
                fvalue = float(r["value"])
                nodes[id] = astree.mk_float_constant(fvalue, optexprid=exprid)

            elif tag == "string-constant":
                exprid = r["exprid"]
                cstr = r["cstr"]
                va = r["va"] if "va" in r else None
                if r["args"][0] == -1:
                    addrexpr: Optional[AST.ASTExpr] = None
                else:
                    addrexpr = cast(AST.ASTExpr, mk_node(arg(0)))
                nodes[id] = astree.mk_string_constant(
                    addrexpr, cstr, va, optexprid=exprid)

            elif tag == "lval-expr":
                exprid = r["exprid"]
                lval = cast(AST.ASTLval, mk_node(arg(0)))
                nodes[id] = astree.mk_lval_expression(lval, optexprid=exprid)

            elif tag == "cast-expr":
                exprid = r["exprid"]
                tgttyp = cast(AST.ASTTyp, mk_node(arg(0)))
                expr = cast(AST.ASTExpr, mk_node(arg(1)))
                nodes[id] = astree.mk_cast_expression(
                    tgttyp, expr, optexprid=exprid)

            elif tag == "sizeof-expr":
                exprid = r["exprid"]
                tgttyp = cast(AST.ASTTyp, mk_node(arg(0)))
                nodes[id] = astree.mk_sizeof_expression(tgttyp, optexprid=exprid)

            elif tag == "address-of":
                exprid = r["exprid"]
                lval = cast(AST.ASTLval, mk_node(arg(0)))
                nodes[id] = astree.mk_address_of_expression(
                    lval, optexprid=exprid)

            elif tag == "unary-op":
                exprid = r["exprid"]
                exp1 = cast(AST.ASTExpr, mk_node(arg(0)))
                op = r["op"]
                nodes[id] = astree.mk_unary_expression(op, exp1, optexprid=exprid)

            elif tag == "binary-op":
                exprid = r["exprid"]
                exp1 = cast(AST.ASTExpr, mk_node(arg(0)))
                exp2 = cast(AST.ASTExpr, mk_node(arg(1)))
                op = r["op"]
                nodes[id] = astree.mk_binary_expression(
                    op, exp1, exp2, optexprid=exprid)

            elif tag == "question":
                exprid = r["exprid"]
                exp1 = cast(AST.ASTExpr, mk_node(arg(0)))
                exp2 = cast(AST.ASTExpr, mk_node(arg(1)))
                exp3 = cast(AST.ASTExpr, mk_node(arg(2)))
                nodes[id] = astree.mk_question_expression(
                    exp1, exp2, exp3, optexprid=exprid)

            elif tag == "assign":
                instrid = r["instrid"]
                locationid = r["locationid"]
                lhs = cast(AST.ASTLval, mk_node(arg(0)))
                rhs = cast(AST.ASTExpr, mk_node(arg(1)))
                nodes[id] = astree.mk_assign(
                    lhs, rhs, optinstrid=instrid, optlocationid=locationid)
                self._annotations[instrid] = [
                    "instrid:" + str(instrid),
                    "lhs:" + str(lhs.lvalid),
                    "rhs:" + str(rhs.exprid)]

            elif tag == "call":
                instrid = r["instrid"]
                locationid = r["locationid"]
                if r["args"][0] == -1:
                    optlhs: Optional[AST.ASTLval] = None
                else:
                    optlhs = cast(AST.ASTLval, mk_node(arg(0)))
                tgtxpr = cast(AST.ASTExpr, mk_node(arg(1)))
                callargs = [
                    cast(AST.ASTExpr, mk_node(records[i]))
                    for i in r["args"][2:]]
                nodes[id] = astree.mk_call(
                    optlhs,
                    tgtxpr,
                    callargs,
                    optinstrid=instrid,
                    optlocationid=locationid)

            elif tag == "return":
                stmtid = r["stmtid"]
                locationid = r["locationid"]
                if r["args"][0] == -1:
                    returnexpr: Optional[AST.ASTExpr] = None
                else:
                    returnexpr = cast(AST.ASTExpr, mk_node(arg(0)))
                nodes[id] = astree.mk_return_stmt(
                    returnexpr, optstmtid=stmtid, optlocationid=locationid)

            elif tag == "instrs":
                stmtid = r["stmtid"]
                locationid = r["locationid"]
                instrs = [
                    cast(AST.ASTInstruction, mk_node(records[i]))
                    for i in r["args"]]
                nodes[id] = astree.mk_instr_sequence(
                    instrs, optstmtid=stmtid, optlocationid=locationid)

            elif tag == "if":
                stmtid = r["stmtid"]
                locationid = r["locationid"]
                condition = cast(AST.ASTExpr, mk_node(arg(0)))
                thenbranch = cast(AST.ASTStmt, mk_node(arg(1)))
                elsebranch = cast(AST.ASTStmt, mk_node(arg(2)))
                targetaddr = r["destination-addr"]
                nodes[id] = astree.mk_branch(
                    condition,
                    thenbranch,
                    elsebranch,
                    targetaddr,
                    optstmtid=stmtid,
                    optlocationid=locationid)

            elif tag == "block":
                stmtid = r["stmtid"]
                locationid = r["locationid"]
                stmts = [
                    cast(AST.ASTStmt, mk_node(records[i]))
                    for i in r["args"]]
                nodes[id] = astree.mk_block(
                    stmts, optstmtid=stmtid, optlocationid=locationid)

            elif tag == "goto":
                stmtid = r["stmtid"]
                locationid = r["locationid"]
                destinationlabel = r["destination"]
                destinationaddr = r["destination-addr"]
                nodes[id] = astree.mk_goto_stmt(
                    destinationlabel, destinationaddr, stmtid, locationid)

            elif tag == "computedgoto":
                stmtid = r["stmtid"]
                locationid = r["locationid"]
                tgtexpr = cast(AST.ASTExpr, mk_node(arg(0)))
                nodes[id] = astree.mk_computed_goto_stmt(
                    tgtexpr, optstmtid=stmtid, optlocationid=locationid)

            elif tag == "switch":
                stmtid = r["stmtid"]
                locationid = r["locationid"]
                switchexpr = cast(AST.ASTExpr, mk_node(arg(0)))
                cases = cast(AST.ASTStmt, mk_node(arg(1)))
                nodes[id] = astree.mk_switch_stmt(
                    switchexpr, cases, stmtid, locationid)

            elif tag == "break":
                stmtid = r["stmtid"]
                locationid = r["locationid"]
                nodes[id] = astree.mk_break_stmt(
                    optstmtid=stmtid, optlocationid=locationid)

            elif tag == "continue":
                stmtid = r["stmtid"]
                locationid = r["locationid"]
                nodes[id] = astree.mk_continue_stmt(
                    optstmtid=stmtid, optlocationid=locationid)

            elif tag == "loop":
                stmtid = r["stmtid"]
                locationid = r["locationid"]
                body = cast(AST.ASTStmt, mk_node(arg(0)))
                nodes[id] = astree.mk_loop(
                    body, optstmtid=stmtid, optlocationid=locationid)

            elif tag == "label":
                locationid = r["locationid"]
                name = r["name"]
                nodes[id] = astree.mk_label(name, locationid)

            elif tag == "case":
                locationid = r["locationid"]
                expr = cast(AST.ASTExpr, mk_node(arg(0)))
                nodes[id] = astree.mk_case_label(expr, locationid)

            elif tag == "caserange":
                locationid = r["locationid"]
                lowexpr = cast(AST.ASTExpr, mk_node(arg(0)))
                highexpr = cast(AST.ASTExpr, mk_node(arg(1)))
                nodes[id] = astree.mk_case_range_label(
                    lowexpr, highexpr, locationid)

            elif tag == "default":
                locationid = r["locationid"]
                nodes[id] = astree.mk_default_label(locationid)

            else:
                raise Exception("Deserializer: tag " + tag + " not handled")

            if id in nodes:
                return nodes[id]
            else:
                raise Exception("Deserializer: No node created for " + str(id))

        # Process enuminfos first, so their names are known for compinfo fields
        for r in records.values():
            if r["tag"] == "enuminfo":
                mk_node(r)

        for r in records.values():
            if r["tag"] != "enuminfo":
                mk_node(r)

        return nodes

    def return_sequences_for(self, addr: str) -> ASTReturnSequences:
        fdata = None
        for _fdata in self.serialization["functions"]:
            if addr == _fdata["va"]:
                fdata = _fdata
                break
        if fdata is None:
            raise ValueError("Function %s not found in serialization" % addr)

        code_fragments = ASTCodeFragments()
        code_fragments.deserialize(self.serialization["codefragments"])

        return_sequences = ASTReturnSequences(code_fragments)
        return_sequences.deserialize(fdata["return-sequences"])

        return return_sequences
