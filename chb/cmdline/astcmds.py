# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022 Aarno Labs, LLC
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
"""Commands related to decompilation and generation of abstract syntax trees."""

import argparse
import json
import os

from typing import Any, cast, Dict, List, NoReturn, Set, Tuple, TYPE_CHECKING

from chb.app.AppAccess import AppAccess

from chb.ast.ASTBasicCTyper import ASTBasicCTyper
from chb.ast.ASTByteSizeCalculator import ASTByteSizeCalculator
from chb.ast.ASTDeserializer import ASTDeserializer
from chb.ast.ASTLiveCode import ASTLiveCode
from chb.ast.ASTNode import ASTStmt, ASTExpr, ASTVariable
from chb.ast.ASTCPrettyPrinter import ASTCPrettyPrinter
from chb.ast.ASTSerializer import ASTSerializer
from chb.ast.ASTSymbolTable import ASTGlobalSymbolTable, ASTLocalSymbolTable
from chb.ast.ASTExprPropagator import ASTExprPropagator

from chb.astinterface.ASTInterface import ASTInterface
from chb.astinterface.ASTRewriter import ASTRewriter
from chb.astinterface.BC2ASTConverter import BC2ASTConverter

import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

from chb.userdata.UserHints import UserHints

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.bctypes.BCCompInfo import BCCompInfo    
    from chb.bctypes.BCTyp import BCTypComp


def reduce_ast_nodes(
        records: List[Dict[str, Any]],
        livestmts: Set[int]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []

    index: Dict[int, Dict[str, Any]] = {}
    for r in records:
        index[r["id"]] = r

    def stmt_is_live(id: int) -> bool:
        return (index[id]["assembly-xref"] in livestmts)

    for r in records:
        if r["tag"] in ["block", "instrs"]:
            if stmt_is_live(r["id"]):
                newrecord: Dict[str, Any] = {}
                newargs: List[int] = []
                for id in r["args"]:
                    if stmt_is_live(id):
                        newargs.append(id)
                newrecord["assembly-xref"] = r["assembly-xref"]
                newrecord["tag"] = r["tag"]
                newrecord["args"] = newargs
                newrecord["id"] = r["id"]
                result.append(newrecord)
            else:
                continue
        elif r["tag"] == "if":
            if stmt_is_live(r["id"]):
                newrecord = {}
                newargs = []
                newargs.append(r["args"][0])   # condition expr id
                newargs.append(r["args"][1])   # then branch
                newargs.append(r["args"][2])   # else branch
                newrecord["tag"] = r["tag"]
                newrecord["assembly-xref"] = r["assembly-xref"]
                newrecord["args"] = newargs
                newrecord["id"] = r["id"]
                newrecord["pc-offset"] = r["pc-offset"]
                result.append(newrecord)
            else:
                continue
        else:
            result.append(r)

    return result


def showast(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    outputfile: str = args.outputfile
    decompile: bool = args.decompile
    exclude: List[str] = args.exclude
    functions: List[str] = args.functions
    hints: List[str] = args.hints  # names of json files
    remove_edges: List[str] = args.remove_edges
    add_edges: List[str] = args.add_edges
    verbose: bool = args.verbose
    available_exprs: List[str] = args.show_available_exprs

    if (not decompile) and len(functions) == 0:
        UC.print_error(
            "Please specify at least one function address\n"
            + "with the --functions command-line option.")
        exit(1)

    rmedges: Dict[str, List[Tuple[str, str]]] = {}
    adedges: Dict[str, List[Tuple[str, str]]] = {}
    if len(remove_edges) + len(add_edges) > 0:
        rmedges = UC.extract_function_edges(remove_edges)
        adedges = UC.extract_function_edges(add_edges)

    try:
        (path, xfile) = UC.get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    # read hints files
    os.chdir(path)
    userhints = UserHints(toxml=False)
    filenames = [os.path.abspath(s) for s in hints]
    if len(filenames) > 0:
        print("use hints files: " + ", ".join(filenames))
        for filename in filenames:
            try:
                with open(filename, "r") as fp:
                    fuserdata = json.load(fp)
                if "userdata" in fuserdata:
                    userhints.add_hints(fuserdata["userdata"])
                else:
                    UC.print_error(
                        "Expected to find userdata in " + filename)
                    exit(1)
            except Exception as e:
                UC.print_error(
                    "Error in reading " + filename + ": " + str(e))
                exit(1)

    if UF.file_has_registered_userdata(xinfo.md5):
        print("Use registered userdata.")
        userdata = UF.get_file_registered_userdata(xinfo.md5)
        userhints.add_hints(userdata)

    jsonfilenames: Dict[str, str] = {}

    app = UC.get_app(path, xfile, xinfo)

    excluded: int = 0
    if decompile:
        for (faddr, fn) in app.functions.items():
            if faddr in exclude or fn.cfg.has_loops():
                excluded += 1
                continue
            functions.append(faddr)

    functioncount: int = 0
    failedfunctions: int = 0
    opc_unsupported: Dict[str, int] = {}    # instr mnemonic -> count

    # --------------------------------------- initialize global symbol table ---

    symbolicaddrs: Dict[str, str] = userhints.symbolic_addresses()
    revsymbolicaddrs = {v: k for (k, v) in symbolicaddrs.items()}
    revfunctionnames = userhints.rev_function_names()

    globalsymboltable = ASTGlobalSymbolTable()    
    typconverter = BC2ASTConverter(app.bcfiles, globalsymboltable)

    for vinfo in app.bcfiles.globalvars:
        vname = vinfo.vname
        if vname in revsymbolicaddrs:
            gaddr = int(revsymbolicaddrs[vname], 16)
        elif vname in revfunctionnames:
            gaddr = int(revfunctionnames[vname], 16)
        else:
            gaddr = 0
        if gaddr > 0:
            globalsymboltable.add_symbol(
                vname,
                vtype=vinfo.vtype.convert(typconverter),
                globaladdress=gaddr)
            # size=vinfo.vtype.byte_size())
    typconverter.initialize_compinfos()

    # ------------------------------------------- initialize json ast output ---

    if outputfile is not None:
        ast_output: Dict[str, Any] = {}
        ast_output["functions"] = []
        astfunctions = ast_output["functions"]

    # ------------------------------------ generate ast / decompile functions ---

    for faddr in functions:
        print("========= Function " + faddr + " ================")
        if app.has_function(faddr):
            f = app.function(faddr)
            if f is None:
                UC.print_error("Unable to find function " + faddr)
                continue

            fnrmedges: List[Tuple[str, str]] = []
            fnadedges: List[Tuple[str, str]] = []
            if faddr in rmedges:
                fnrmedges = rmedges[faddr]
                print("Remove " + str(len(fnrmedges)) + " edge(s) from cfg")
            if faddr in adedges:
                fnadedges = adedges[faddr]
                print("Add " + str(len(fnadedges)) + " edge(s) to cfg")
            if len(fnrmedges) + len(fnadedges) > 0:
                f.cfg.modify_edges(fnrmedges, fnadedges)

            fname = faddr
            if app.has_function_name(faddr):
                fname = app.function_name(faddr)
            else:
                fname = "sub_" + faddr[2:]

            localsymboltable = ASTLocalSymbolTable(
                globalsymboltable)
            ctyper = ASTBasicCTyper(globalsymboltable)
            typesizer = ASTByteSizeCalculator(ctyper)

            astree = ASTInterface(
                faddr,
                fname,
                localsymboltable,
                typconverter,
                typesizer,
                ctyper,
                xinfo.architecture)
            gvars: List[ASTVariable] = []

            if app.bcfiles.has_functiondef(fname):
                fdef = app.bcfiles.functiondef(fname)
                astree.set_fprototype(fdef.svinfo)
                fproto = fdef.svinfo.convert(typconverter)
                localsymboltable.set_function_prototype(fproto)

            elif app.bcfiles.has_vardecl(fname):
                vardecl = app.bcfiles.vardecl(fname)
                astree.set_fprototype(vardecl)
                fproto = vardecl.convert(typconverter)
                localsymboltable.set_function_prototype(fproto)
            
            try:
                ast = f.ast(astree)
            except UF.CHBError as e:
                print("=" * 80)
                print("AST generation is still experimental with limited support.")
                print(
                    "The following is not yet supported for function "
                    + fname
                    + " ("
                    + faddr
                    + ")")
                print(" -- " + str(e))
                print('-' * 80)
                failedfunctions += 1
                if len(astree.diagnostics) > 0:
                    print("Diagnostics: ")
                    print("\n".join(astree.diagnostics))
                continue
            '''
            except Exception as e:
                print("*" * 80)
                print(
                    "Error in AST generation in function: "
                    + fname
                    + " ("
                    + faddr
                    + ")")
                print(str(e))
                print("*" * 80)
                failedfunctions += 1
                continue
            '''

            unsupported = astree.unsupported_instructions
            if len(unsupported) > 0:
                print("=" * 80)
                print("AST generation is still experimental with limited support.")
                print(
                    "We don't yet support the following instructions in "
                    + fname
                    + " ("
                    + faddr
                    + ")")
                print('-' * 80)
                for m in unsupported:
                    opc_unsupported.setdefault(m, 0)
                    opc_unsupported[m] += len(unsupported)
                    print(m)
                    for instr in unsupported[m]:
                        print("  " + instr)
                print('-' * 80)
                failedfunctions += 1
                continue

            ast = cast(ASTStmt, ast)

            if verbose:
                print("Low level AST")
                print("~" * 40)
                prettyprinter = ASTCPrettyPrinter(localsymboltable)
                print(prettyprinter.to_c(ast))
                print("~" * 80)

            addresstaken = ast.address_taken()
            callees = ast.callees()
            # storagerecords = astree.storage_records()

            for i in range(0, 5):
                propagator = ASTExprPropagator()
                ast = propagator.propagate(ast)

            instr_usedefs_e = propagator.instrusedefs

            spans = astree.spans

            if verbose:
                print("\nSpans")
                print("-" * 80)
                for span in spans:
                    print(str(span))
                print("=" * 80)

            spanmap: Dict[int, str] = {}
            for spanrec in spans:
                spanxref = cast(int, (spanrec["xref"]))
                spans_at_xref = cast(List[Dict[str, Any]], spanrec["spans"])
                spanmap[spanxref] = spans_at_xref[0]["base_va"]

            availablexprs: Dict[str, List[Tuple[int, str, str, str]]] = {}
            for instrlabel in instr_usedefs_e:
                if instrlabel in spanmap:
                    addr = spanmap[instrlabel]
                    availablexprs[addr] = cast(List[Tuple[int, str, str, str]], [])
                    for (v, d) in instr_usedefs_e[instrlabel].defs.items():
                        pp = ASTCPrettyPrinter(localsymboltable)
                        lvaltype = d[1].ctype(ctyper)
                        if lvaltype is None:
                            lvaltype = d[2].ctype(ctyper)
                        availablexprs[addr].append(
                            (d[0],
                             v,
                             pp.expr_to_c(d[2]),
                             str(lvaltype)))

            if verbose:
                print("\nAvailable expressions")
                print("-" * 80)
                for s in sorted(availablexprs):
                    print(s)
                    for r in availablexprs[s]:
                        print("  " + str(r))
                print("=" * 80)

            livecode = ASTLiveCode()
            livecode.live_variables_on_entry(ast)
            livestmts = livecode.livecode
            livesymbols = livecode.livesymbols

            if verbose:
                print("Live statements:")
                print(", ".join(str(i) for i in livestmts))
                print("\nLive symbols:")
                print(", ".join(str(s) for s in livesymbols))

            astreduced = ast

            if verbose:
                print("\nPretty printer output before rewriting")
                print("=" * 80)
                prettyprinter = ASTCPrettyPrinter(
                    localsymboltable,
                    livecode=list(livestmts),
                    livesymbols=livesymbols,
                    livevars_on_exit=livecode.live_on_exit)
                print(prettyprinter.to_c(ast))
                print("~" * 80)

            rewriter = ASTRewriter(localsymboltable)
            ast = rewriter.rewrite_code(ast)

            if verbose:
                print("\nRewriter notes:")
                print(str(rewriter))
                print("~" * 80)

            prettyprinter = ASTCPrettyPrinter(
                localsymboltable,
                livecode=list(livestmts),
                livesymbols=livesymbols,
                livevars_on_exit=livecode.live_on_exit)
            print(prettyprinter.to_c(ast))
            print("~" * 80)

            functioncount += 1

            if outputfile is not None:

                astfunction: Dict[str, Any] = {}
                serializer = ASTSerializer()

                localsymboltable.serialize(serializer)
                astfunction["prototype"] = localsymboltable.serialize_function_prototype(
                    serializer)
                startnode = serializer.index_stmt(ast)
                astnodes = serializer.records()

                if app.has_function_name(faddr):
                    astfunction["name"] = app.function_name(faddr)
                astfunction["va"] = faddr
                astfunction["ast"] = {}
                astfunction["ast"]["nodes"] = astnodes
                astfunction["ast"]["lifted-nodes"] = reduce_ast_nodes(astnodes, livestmts)
                astfunction["ast"]["startnode"] = startnode
                astfunction["ast"]["livecode"] = sorted(list(livestmts))
                astfunction["spans"] = astree.spans
                astfunction["available-expressions"] = availablexprs
                astfunctions.append(astfunction)

                if verbose and len(astree.diagnostics) > 0:
                    print("\nNotes")
                    print("=" * 80)
                    print("\n".join(astree.diagnostics))
                    print("=" * 80)

        else:
            UC.print_error("Function " + faddr + " not found")
            exit(1)

    globalserializer = ASTSerializer()
    bccinfos: List["BCCompInfo"] = list(typconverter.compinfos_referenced.values())
    for bccinfo in bccinfos:
        if not globalsymboltable.has_compinfo(bccinfo.ckey):
            bccinfo.convert(typconverter)
    globalsymboltable.serialize(globalserializer)

    if outputfile is not None:
        serializer = ASTSerializer()
        ast_output["global-symbol-table"] = globalserializer.records()

        outputfilename: str = outputfile + ".json"
        with open(outputfilename, "w") as fp:
            json.dump(ast_output, fp, indent=2)
        print("\n" + ("-" * 80))
        print("AST(s) were saved in: " + outputfilename)
        print("-" * 80)

    if outputfile is not None and args.verbose:
        deserializer = ASTDeserializer(ast_output)
        for (symboltable, astnode) in deserializer.functions.values():
            print(deserialize_function(symboltable, astnode))

        print("\nLifted deserialized functions")
        for (symboltable, astnode) in deserializer.lifted_functions.values():
            print(deserialize_function(symboltable, astnode))

    if decompile:
        print("\nStatistics:")
        print("Functions decompiled : " + str(functioncount))
        print("Functions that failed: " + str(failedfunctions))
        print("Functions excluded   : " + str(excluded))
        if len(opc_unsupported) > 0:
            print("Unsupported opcodes: ")
            for (opc, count) in sorted(opc_unsupported.items()):
                print("  " + opc.ljust(10) + str(count).rjust(5))

    exit(0)


def deserialize_function(symboltable: ASTLocalSymbolTable, ast: ASTStmt) -> str:
    lines: List[str] = []

    livecode = ASTLiveCode()
    livecode.live_variables_on_entry(ast)
    livesymbols = livecode.livesymbols

    pp = ASTCPrettyPrinter(symboltable, livesymbols=livesymbols)
    lines.append("Deserialized form:")
    lines.append("=" * 80)
    lines.append(pp.to_c(ast))
    lines.append("=" * 80)
    return "\n".join(lines)


def deserialize(args: argparse.Namespace) -> NoReturn:

    # arguments
    filename: str = args.filename

    if not os.path.isfile(filename):
        UC.print_error(
            "File " + filename + " not found.")
        exit(1)

    with open(filename, "r") as fp:
        astdata = json.load(fp)

    deserializer = ASTDeserializer(astdata)
    for (symboltable, astnode) in deserializer.functions.values():
        print(deserialize_function(symboltable, astnode))

    print("\nLifted deserialized functions")
    for (symboltable, astnode) in deserializer.lifted_functions.values():
        print(deserialize_function(symboltable, astnode))

    exit(0)
