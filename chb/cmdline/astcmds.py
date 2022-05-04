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

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree
from chb.ast.ASTDeserializer import ASTDeserializer
from chb.ast.ASTLiveCode import ASTLiveCode
from chb.ast.ASTNode import ASTStmt, ASTExpr, ASTVariable
from chb.ast.ASTCPrettyPrinter import ASTCPrettyPrinter
from chb.ast.ASTRewriter import ASTRewriter
from chb.ast.ASTSerializer import ASTSerializer
from chb.ast.ASTSymbolTable import ASTGlobalSymbolTable, ASTLocalSymbolTable
from chb.ast.ASTExprPropagator import ASTExprPropagator
from chb.ast.ASTUtil import InstrUseDef, UseDef

import chb.cmdline.commandutil as UC
import chb.cmdline.XInfo as XI

from chb.userdata.UserHints import UserHints

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.bctypes.BCTyp import BCTypComp


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

    globalsymboltable = ASTGlobalSymbolTable(xinfo.architecture)

    for vinfo in app.bcfiles.globalvars:
        vname = vinfo.vname
        if vname in revsymbolicaddrs:
            gaddr = int(revsymbolicaddrs[vname], 16)
        elif vname in revfunctionnames:
            gaddr = int(revfunctionnames[vname], 16)
        else:
            gaddr = 0
        globalsymboltable.add_global_symbol(
            vname,
            vtype=vinfo.vtype,
            globaladdress=gaddr,
            size=vinfo.vtype.byte_size())

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
                globalsymboltable, xinfo.architecture)

            if app.bcfiles.has_functiondef(fname):
                fdef = app.bcfiles.functiondef(fname)
                localsymboltable.set_functiondef(fdef)
                localsymboltable.set_function_prototype(fdef.svinfo)            

            astree = AbstractSyntaxTree(
                faddr,
                fname,
                localsymboltable)
            gvars: List[ASTVariable] = []

            if app.bcfiles.has_functiondef(fname):
                fdef = app.bcfiles.functiondef(fname)
                astree.set_functiondef(fdef)
                astree.set_function_prototype(fdef.svinfo)
            elif app.bcfiles.has_vardecl(fname):
                fdecl = app.bcfiles.vardecl(fname)
                astree.set_function_prototype(fdecl)

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
                if len(astree.diagnostics()) > 0:
                    print("Diagnostics: ")
                    print("\n".join(astree.diagnostics()))
                continue
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

            addresstaken = ast.address_taken()
            callees = ast.callees()
            storagerecords = astree.storage_records()

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

            if verbose:
                print(ast.to_c_like(sp=3))

            spanmap: Dict[int, str] = {}
            for spanrec in spans:
                spanid = cast(int, (spanrec["id"]))
                spans_at_id = cast(List[Dict[str, Any]], spanrec["spans"])
                spanmap[spanid] = spans_at_id[0]["base_va"]

            availablexprs: Dict[str, List[Tuple[int, str, str, str]]] = {}
            for instrlabel in instr_usedefs_e:
                if instrlabel in spanmap:
                    addr = spanmap[instrlabel]
                    availablexprs[addr] = cast(List[Tuple[int, str, str, str]], [])
                    for (v, d) in instr_usedefs_e[instrlabel].defs.items():
                        lvaltype = d[1].ctype
                        if lvaltype is None:
                            lvaltype = d[2].ctype
                        availablexprs[addr].append(
                            (d[0], v, d[2].to_c_like(), str(lvaltype)))

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

            astreduced = ast

            if verbose:
                print("\nPretty printer output before rewriting")
                print("=" * 80)
                prettyprinter = ASTCPrettyPrinter(
                    localsymboltable,
                    globalsymboltable,
                    livecode=list(livestmts),
                    livesymbols=livesymbols,
                    livevars_on_exit = livecode.live_on_exit)
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
                globalsymboltable,
                livecode=list(livestmts),
                livesymbols=livesymbols,
                livevars_on_exit = livecode.live_on_exit)
            print(prettyprinter.to_c(ast))
            print("~" * 80)
            
            functioncount += 1

            '''
            print("")
            if astree.symboltable.has_function_prototype():
                print(str(astree.symboltable.function_prototype) + "{")
            else:
                print("int " + fname + "(?)")
            print(astreduced.to_c_like(sp=3))
            print("}\n")
            '''

            if outputfile is not None:

                serializer = ASTSerializer()
                startnode = serializer.index_stmt(ast)
                astnodes = serializer.records()

                astfunction: Dict[str, Any] = {}
                if app.has_function_name(faddr):
                    astfunction["name"] = app.function_name(faddr)
                astfunction["va"] = faddr
                astfunction["local-symbol-table"] = localsymboltable.serialize()
                astfunction["ast"] = {}
                astfunction["ast"]["nodes"] = astnodes
                astfunction["ast"]["startnode"] = startnode
                astfunction["ast"]["livecode"] = sorted(list(livestmts))
                astfunction["spans"] = astree.spans
                astfunction["available-expressions"] = availablexprs
                astfunction["storage"] = storagerecords
                astfunctions.append(astfunction)

                if verbose and len(astree.notes) > 0:
                    print("\nNotes")
                    print("=" * 80)
                    print("\n".join(astree.notes))
                    print("=" * 80)

        else:
            UC.print_error("Function " + faddr + " not found")
            exit(1)

    print("\nGlobal symboltable")
    print(str(globalsymboltable))

    print("\nTypes used")
    for ix in globalsymboltable.types_used:
        t = app.bcdictionary.typ(ix)
        if t.is_struct:
            t = cast("BCTypComp", t)
            compinfo = t.compinfo
            print(str(compinfo))
        else:
            print(str(app.bcdictionary.typ(ix)) + " (" + str(ix) + ")")

    if outputfile is not None:
        ast_output["global-symbol-table"] = globalsymboltable.serialize()
        ast_output["struct-types"] = {}
        for ix in globalsymboltable.types_used:
            t = app.bcdictionary.typ(ix)
            if t.is_struct:
                t = cast("BCTypComp", t)
                compinfo = t.compinfo
                ast_output["struct-types"][compinfo.cname] = str(compinfo)

        outputfilename: str = outputfile + ".json"
        with open(outputfilename, "w") as fp:
            json.dump(ast_output, fp, indent=2)
        print("\n" + ("-" * 80))
        print("AST(s) were saved in: " + outputfilename)
        print("-" * 80)

    if outputfile is not None and args.verbose:
        print_deserialization(ast_output)              

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


def print_deserialization(ast_output: Dict[str, Any]) -> None:

    globaltable = ast_output["global-symbol-table"]
    print_deserialized_symboltable(globaltable)
    print_types_used(ast_output["struct-types"])
    print("")
    for f in ast_output["functions"]:
        deserializer = ASTDeserializer(
            f["ast"]["nodes"],
            f["ast"]["startnode"],
            f["ast"]["livecode"],
            globaltable,
            f["local-symbol-table"],
            f["available-expressions"],
            f["spans"])
        print("\nDeserialized lifted ast")
        # print(str(deserializer.to_c_like()))


def print_deserialized_symboltable(table: Dict[str, Any]) -> None:
    for (vname, vinfo) in sorted(table.items()):
        if "type" in vinfo:
            print(vinfo["type"] + " " + vname + ";")
        else:
            print("? " + vname)

def print_types_used(table: Dict[str, str]) -> None:
    for (name, ty) in table.items():
        print(name)
        print(ty)
        print("")
        
    
    
