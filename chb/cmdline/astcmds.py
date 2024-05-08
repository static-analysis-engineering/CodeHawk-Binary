# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2024  Aarno Labs, LLC
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

import logging

import argparse
import json
import os

from typing import (
    Any, cast, Dict, List, NoReturn, Optional, Set, Tuple, TYPE_CHECKING)

from chb.app.AppAccess import AppAccess

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree
from chb.ast.ASTApplicationInterface import ASTApplicationInterface
from chb.ast.ASTBasicCTyper import ASTBasicCTyper
from chb.ast.ASTByteSizeCalculator import ASTByteSizeCalculator
from chb.ast.ASTDeserializer import ASTDeserializer
from chb.ast.ASTNode import ASTStmt, ASTExpr, ASTVariable, ASTVarInfo
from chb.ast.ASTCPrettyPrinter import ASTCPrettyPrinter
from chb.ast.ASTReturnSequences import ASTReturnSequences
from chb.ast.ASTSerializer import ASTSerializer
from chb.ast.ASTSymbolTable import ASTGlobalSymbolTable, ASTLocalSymbolTable

from chb.astinterface.ASTInterface import ASTInterface
from chb.astinterface.ASTInterfaceFunction import ASTInterfaceFunction
from chb.astinterface.BC2ASTConverter import BC2ASTConverter
from chb.astinterface.CHBASTSupport import CHBASTSupport

import chb.cmdline.commandutil as UC
from chb.cmdline.PatchResults import PatchResults, PatchEvent
import chb.cmdline.XInfo as XI

from chb.userdata.UserHints import UserHints

import chb.util.fileutil as UF
from chb.util.loggingutil import chklogger, LogLevel


if TYPE_CHECKING:
    from chb.api.AppFunctionSignature import AppFunctionSignature
    from chb.bctypes.BCCompInfo import BCCompInfo
    from chb.bctypes.BCTyp import BCTypComp
    from chb.bctypes.BCVarInfo import BCVarInfo


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


def library_call_targets(app: AppAccess, faddrs: List[str]) -> List[str]:
    """Return a list of names of dynamically loaded library functions used."""

    result: Set[str] = set([])
    for faddr in faddrs:
        if app.has_function(faddr):
            f = app.function(faddr)
            fcallees = f.call_instructions()
            for b in fcallees:
                for instr in fcallees[b]:
                    calltgt = instr.call_target
                    if calltgt.is_so_target:
                        result.add(calltgt.name)
    return list(result)


def buildast(args: argparse.Namespace) -> NoReturn:

    # arguments
    xname: str = args.xname
    outputfile: str = args.outputfile
    functions: List[str] = args.functions
    hints: List[str] = args.hints  # names of json files
    xpatchresultsfile = args.patch_results_file
    remove_edges: List[str] = args.remove_edges
    add_edges: List[str] = args.add_edges
    verbose: bool = args.verbose
    loglevel: str = args.loglevel
    logfilename: Optional[str] = args.logfilename
    logfilemode: str = args.logfilemode

    try:
        (path, xfile) = UC.get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    UC.set_logging(
        loglevel,
        path,
        logfilename=logfilename,
        mode=logfilemode,
        msg="results ast invoked")

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    patchresultsdata: Optional[Dict[str, Any]] = None
    if xpatchresultsfile is not None:
        with open(xpatchresultsfile, "r") as fp:
            patchresultsdata = json.load(fp)

    patchevents: Dict[str, PatchEvent] = {}

    if patchresultsdata is not None:
        patchresults = PatchResults(patchresultsdata)
        for event in patchresults.events:
            if (
                    event.is_trampoline
                    or event.is_trampoline_pair_minimal_2_and_3):
                if event.has_wrapper():
                    startaddr = event.wrapper.vahex
                    patchevents[startaddr] = event

    # read hints files
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

    app = UC.get_app(path, xfile, xinfo)

    support = CHBASTSupport()
    astapi = ASTApplicationInterface(support=support)

    # --------------------------------------- initialize global symbol table ---

    symbolicaddrs: Dict[str, str] = userhints.symbolic_addresses()
    revsymbolicaddrs = {v: k for (k, v) in symbolicaddrs.items()}
    revfunctionnames = userhints.rev_function_names()
    varintros = userhints.variable_introductions()

    if len(varintros) == 0:
        varintros = app.systeminfo.varintros

    library_targets = library_call_targets(app, functions)

    globalsymboltable = astapi.globalsymboltable
    codefragments = astapi.codefragments
    typconverter = BC2ASTConverter(app.bcfiles, globalsymboltable)

    fnames: Dict[str, str] = {}
    for faddr in app.appfunction_addrs:
        if app.has_function_name(faddr):
            fname = app.function_name(faddr)
            fnames[fname] = faddr

    for vinfo in app.bcfiles.globalvars:
        vname = vinfo.vname
        if vname in revsymbolicaddrs:
            gaddr = int(revsymbolicaddrs[vname], 16)
        elif vname in revfunctionnames:
            gaddr = int(revfunctionnames[vname], 16)
        elif vname in fnames:
            gaddr = int(fnames[vname], 16)
        else:
            gaddr = 0
        # if gaddr > 0 or vname in library_targets:
        if True:
            globalsymboltable.add_symbol(
                vname,
                vtype=vinfo.vtype.convert(typconverter),
                globaladdress=gaddr)

    typconverter.initialize_enuminfos(app.bcfiles.genumtags)
    typconverter.initialize_compinfos()

    functions_lifted: int = 0
    functions_failed: int = 0

    for faddr in functions:
        if app.has_function(faddr):
            f = app.function(faddr)
            fsummary = f.finfo.appsummary
            if f is None:
                UC.print_error("Unable to find function " + faddr)
                continue

            if app.has_function_name(faddr):
                fname = app.function_name(faddr)
            else:
                fname = "sub_" + faddr[2:]

            localsymboltable = ASTLocalSymbolTable(globalsymboltable)
            returnsequences = ASTReturnSequences(codefragments)
            astree = AbstractSyntaxTree(
                faddr,
                fname,
                localsymboltable,
                returnsequences=returnsequences,
                registersizes=support.register_sizes,
                flagnames=support.flagnames)

            srcprototype: Optional["BCVarInfo"] = None
            astprototype: Optional[ASTVarInfo] = None
            appsignature: Optional["AppFunctionSignature"] = None
            if app.bcfiles.has_vardecl(fname):
                srcprototype = app.bcfiles.vardecl(fname)
                if fsummary is not None:
                    appsignature = fsummary.function_signature
            elif fname == "main":
                astprototype = astree.mk_vinfo_main_function(faddr)

            astinterface = ASTInterface(
                astree,
                typconverter,
                xinfo.architecture,
                srcprototype=srcprototype,
                astprototype=astprototype,
                appsignature=appsignature,
                varintros=varintros,
                verbose=verbose)

            astfunction = ASTInterfaceFunction(
                faddr, fname, f, astinterface, patchevents=patchevents)

            try:
                asts = astfunction.mk_asts(support)
            except UF.CHBError as e:
                UC.print_error(
                    "Unable to create lifting for "
                    + faddr
                    + ":\n"
                    + ("-" * 80)
                    + "\n"
                    + str(e))
                functions_failed += 1
                # continue
                raise

            if len(asts) >= 2:
                astapi.add_function_ast(astree, asts, verbose)

                print("\nLifted code for function " + faddr)
                print("--------------------------------------------------------")
                prettyprinter = ASTCPrettyPrinter(
                    localsymboltable, annotations=astinterface.annotations)
                print(prettyprinter.to_c(asts[0]))
                functions_lifted += 1

            else:
                print("\nUnable to generate a lifting for " + faddr)
                functions_failed += 1
                continue

        else:
            UC.print_error("Unable to find function " + faddr)
            functions_failed += 1
            continue

    if verbose:
        print("\nGlobal symbol table")
        print("=" * 25)
        print(str(globalsymboltable))
        print("\n\n")

    astdata = astapi.serialize(verbose)

    if outputfile is not None:
        filename = outputfile + ".json"
        with open(filename, "w") as fp:
            json.dump(astdata, fp, indent=2)

    if functions_lifted > 1:
        print("Successfully lifted " + str(functions_lifted) + " functions")
    if functions_failed > 0:
        print("Failures: " + str(functions_failed) + " functions")

    chklogger.logger.info("results ast completed")

    exit(0)


def showast(args: argparse.Namespace) -> NoReturn:
    print("still under construction ..")
    exit(1)

    '''
    # arguments
    xname: str = args.xname
    exclude: List[str] = args.exclude
    functions: List[str] = args.functions
    hints: List[str] = args.hints  # names of json files
    verbose: bool = args.verbose

    try:
        (path, xfile) = UC.get_path_filename(xname)
        UF.check_analysis_results(path, xfile)
    except UF.CHBError as e:
        print(str(e.wrap()))
        exit(1)

    xinfo = XI.XInfo()
    xinfo.load(path, xfile)

    # read hints files
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

    app = UC.get_app(path, xfile, xinfo)

    excluded: int = 0
    for (faddr, fn) in app.functions.items():
        if faddr in exclude:
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

    fnames: Dict[str, str] = {}
    for faddr in functions:
        if app.has_function_name(faddr):
            fname = app.function_name(faddr)
            fnames[fname] = faddr

    for vinfo in app.bcfiles.globalvars:
        vname = vinfo.vname
        if vname in revsymbolicaddrs:
            gaddr = int(revsymbolicaddrs[vname], 16)
        elif vname in revfunctionnames:
            gaddr = int(revfunctionnames[vname], 16)
        elif vname in fnames:
            gaddr = int(fnames[vname], 16)
        else:
            gaddr = 0
        if gaddr > 0:
            globalsymboltable.add_symbol(
                vname,
                vtype=vinfo.vtype.convert(typconverter),
                globaladdress=gaddr)

    typconverter.initialize_enuminfos(app.bcfiles.genumtags)
    typconverter.initialize_compinfos()

    functions_lifted: int = 0
    functions_failed: int = 0

    # ------------------------------------ generate ast / decompile functions ---

    for faddr in functions:
        print("========= Function " + faddr + " ================")
        if app.has_function(faddr):
            f = app.function(faddr)
            if f is None:
                UC.print_error("Unable to find function " + faddr)
                continue

            fname = faddr
            if app.has_function_name(faddr):
                fname = app.function_name(faddr)
            else:
                fname = "sub_" + faddr[2:]

            localsymboltable = ASTLocalSymbolTable(globalsymboltable)
            # ctyper = ASTBasicCTyper(globalsymboltable)
            # typesizer = ASTByteSizeCalculator(ctyper)

            astree = AbstractSyntaxTree(
                faddr,
                fname,
                localsymboltable,
                registersizes=support.register_sizes,
                flagnames=support.flagnames)

            srcprototype: Optional["BCVarInfo"] = None
            astprototype: Optional[ASTVarInfo] = None
            if app.bcfiles.has_vardecl(fname):
                srcprototype = app.bcfiles.vardecl(fname)
            elif fname == "main":
                astprototype = astree.mk_vinfo_main_function(faddr)

            astinterface = ASTInterface(
                astree,
                typconverter,
                xinfo.architecture,
                srcprototype=srcprototype,
                astprototype=astprototype,
                varintros=varintros,
                verbose=verbose,
                showdiagnostics=showdiagnostics)

            astfunction = ASTInterfaceFunction(faddr, fname, f, astinterface)

            try:
                asts = astfunction.mk_asts(support)
            except UF.CHBError as e:
                UC.print_error(
                    "Unable to create lifting for "
                    + faddr
                    + ":\n"
                    + ("-" * 80)
                    + "\n"
                    + str(e))
                functions_failed += 1
                # continue
                raise


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
    '''

def deserialize_function(symboltable: ASTLocalSymbolTable, ast: ASTStmt) -> str:
    lines: List[str] = []

    pp = ASTCPrettyPrinter(symboltable)
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
