# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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

import argparse
import json
import os
import subprocess
import sys

import xml.etree.ElementTree as ET

from typing import Any, Dict, List, NoReturn, Optional

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree
from chb.ast.ASTCPrettyPrinter import ASTCPrettyPrinter
from chb.ast.ASTDeserializer import ASTDeserializer
import chb.ast.ASTNode as AST
from chb.ast.ASTViewer import ASTViewer
import chb.ast.astdotutil as DU

from chb.astparser.ASTCParseManager import ASTCParseManager


def print_pirinfo(pirjson: Dict[str, Any]) -> None:
    print("PIR-version: " + pirjson["pir-version"])
    if "created-by" in pirjson:
        cb = pirjson["created-by"]
        print(
            "Created by : "
            + cb["tool-name"]
            + " version "
            + cb["tool-version"]
            + " at "
            + cb["time"])

    print("\nContents:")
    print(
        "Global symbol table: "
        + str(len(pirjson["global-symbol-table"])).rjust(4)
        + " records")
    print(
        "Code fragments     : "
        + str(len(pirjson["codefragments"])).rjust(4)
        + " records")
    print("\nFunctions:")
    for fn in pirjson["functions"]:
        print("  " + fn["name"] + " at address " + fn["va"])
        print("    ast nodes       : " + str(len(fn["ast"]["nodes"])).rjust(4))
        print(
            "    start nodes     : ["
            + ", ".join(str(i) for i in fn["ast"]["ast-startnodes"])
            + "]")
        print("    spans           : " + str(len(fn["spans"])).rjust(4))
        print("    storage         : " + str(len(fn["storage"])).rjust(4))
        print("    return sequences: " + str(len(fn["return-sequences"])).rjust(4))
        print("    available exprs : " + str(len(fn["available-expressions"])).rjust(4))
        if "provenance" in fn:
            prov = fn["provenance"]
            print("    provenance      : ")
            print(
                "      instruction-mapping : "
                + str(len(prov["instruction-mapping"])).rjust(4))
            print(
                "      expression-mapping  : "
            + str(len(prov["expression-mapping"])).rjust(4))
            print(
                "      lval-mapping        : "
                + str(len(prov["lval-mapping"])).rjust(4))
            print(
                "      reaching-definitions: "
                + str(len(prov["reaching-definitions"])).rjust(4))
            print(
                "      flag-reaching-defs  : "
                + str(len(prov["flag-reaching-definitions"])).rjust(4))
            print(
                "      definitions-used    : "
                + str(len(prov["definitions-used"])).rjust(4))



def print_error(m: str) -> None:
    sys.stderr.write(("*" * 80) + "\n")
    sys.stderr.write(m + "\n")
    sys.stderr.write(("*" * 80) + "\n")


def infocmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    pirfile: str = args.pirfile

    with open(pirfile, "r") as fp:
        pirjson = json.load(fp)

    print_pirinfo(pirjson)

    exit(0)


def get_function_addr(pirjson: Dict[str, Any], function: Optional[str]) -> str:
    """Return the hex function address associated with the name function."""

    functions: Dict[str, str] = {}
    for fn in pirjson["functions"]:
        functions[fn["va"]] = fn["name"]

    if function is None:
        print_error(
            "Please list one or more functions. Functions available:"
            + "\n"
                + "\n".join(
                    ("    " + va.ljust(8) + name) for (va, name) in functions.items())
            + "\nSpecify either name or address via --function")
        exit(1)

    if function in functions.keys():
        return function
    else:
        for (va, name) in functions.items():
            if function == name:
                return va
        else:
            print_error(
                "Function " + function + " not found."
                + "\nFunctions present (use either address or name): "
                + "\n"
                + "\n".join(
                    ("    " + va.ljust(8) + name) for (va, name) in functions.items()))
            exit(1)


def view_ast_function(
        faddr: str,
        level: str,
        pirjson: Dict[str, Any],
        cutoff: Optional[str] = None) -> DU.ASTDotGraph:

    deserializer = ASTDeserializer(pirjson)
    (globaltable, dfns) = deserializer.deserialize()
    for dfn in dfns:
        if dfn.astree.faddr == faddr:
            viewer = ASTViewer(faddr, dfn.astree, astcutoff=cutoff)
            if level == "high":
                g = viewer.to_graph(dfn.high_level_ast)
            elif level == "low":
                g = viewer.to_graph(dfn.low_level_ast)
            else:
                g = viewer.to_graph(dfn.high_unreduced_ast)
    return g


def viewastcmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    pirfile: str = args.pirfile
    function: Optional[str] = args.function
    level: str = args.level
    outputfilename: str = args.outputfile
    cutoff: Optional[str] = args.cutoff

    with open(pirfile, "r") as fp:
        pirjson = json.load(fp)

    faddr = get_function_addr(pirjson, function)
    g = view_ast_function(faddr, level, pirjson, cutoff)
    DU.print_dot(outputfilename, g)
    exit(0)


def viewinstrcmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    pirfile: str = args.pirfile
    function: Optional[str] = args.function
    instrid: int = args.instrid
    provenance: bool = args.provenance
    outputfilename: str = args.output

    with open(pirfile, "r") as fp:
        pirjson = json.load(fp)

    faddr = get_function_addr(pirjson, function)
    deserializer = ASTDeserializer(pirjson)
    (globaltable, dfns) = deserializer.deserialize()
    for dfn in dfns:
        if dfn.astree.faddr == faddr:
            instr = dfn.get_instruction(instrid)
            viewer = ASTViewer(faddr, dfn.astree)
            provinstrs: List[AST.ASTInstruction] = []
            if provenance:
                if instrid in dfn.astree.provenance.instruction_mapping:
                    provinstrids = (
                        dfn.astree.provenance.instruction_mapping[instrid])
                    provinstrs = [dfn.get_instruction(i) for i in provinstrids]
                g = viewer.instr_to_graph(instr, provinstrs)
            else:
                g = viewer.instr_to_graph(instr)

            DU.print_dot(outputfilename, g)

    exit(0)


def viewexprcmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    pirfile: str = args.pirfile
    function: Optional[str] = args.function
    exprid: int = args.exprid
    provenance: bool = args.provenance
    reachingdefs: bool = args.reachingdefs
    outputfilename: str = args.output

    with open(pirfile, "r") as fp:
        pirjson = json.load(fp)

    faddr = get_function_addr(pirjson, function)
    deserializer = ASTDeserializer(pirjson)
    (globaltable, dfns) = deserializer.deserialize()
    for dfn in dfns:
        if dfn.astree.faddr == faddr:
            expr = dfn.get_expression(exprid)
            provexpr: Optional[AST.ASTExpr] = None
            rdefs: List[AST.ASTInstruction] = []
            viewer = ASTViewer(faddr, dfn.astree)
            if provenance:
                if exprid in dfn.astree.provenance.expression_mapping:
                    provexprid = dfn.astree.provenance.expression_mapping[exprid]
                    provexpr = dfn.get_expression(provexprid)
            if reachingdefs:
                if exprid in dfn.astree.provenance.reaching_definitions:
                    rdefids = dfn.astree.provenance.reaching_definitions[exprid]
                    rdefs = [dfn.get_instruction(i) for i in rdefids]
            g = viewer.expr_to_graph(expr, provexpr, rdefs)
            DU.print_dot(outputfilename, g)

    exit(0)


def showaexprscmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    pirfile: str = args.pirfile
    function: Optional[str] = args.function
    variables: List[str] = args.variables
    locations: List[str] = args.locations

    with open(pirfile, "r") as fp:
        pirjson = json.load(fp)

    def include_var(var: str) -> bool:
        return len(variables) == 0 or var in variables

    def include_loc(loc: str) -> bool:
        return len(locations) == 0 or loc in locations

    faddr = get_function_addr(pirjson, function)
    deserializer = ASTDeserializer(pirjson)
    (globaltable, dfns) = deserializer.deserialize()
    for dfn in dfns:
        if dfn.astree.faddr == faddr:
            for (addr, aexpr) in dfn.astree.available_expressions.items():
                if include_loc(addr):
                    print(addr)
                    for (var, exprec) in aexpr.items():
                        if include_var(var):
                            print(
                                "  "
                                + var.ljust(14)
                                + ": "
                                + exprec[2]
                                + " ("
                                + str(exprec[0])
                                + ", "
                                + str(exprec[1])
                                + ")")
    exit(0)


def printsrccmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    pirfile: str = args.pirfile
    function: str = args.function

    with open(pirfile, "r") as fp:
        pirjson = json.load(fp)

    faddr = get_function_addr(pirjson, function)
    deserializer = ASTDeserializer(pirjson)
    (symtable, astnode) = deserializer.lifted_functions[faddr]
    pp = ASTCPrettyPrinter(symtable, annotations=deserializer.annotations)
    print(pp.to_c(astnode, include_globals=True))

    exit(0)


def parsecmd(args: argparse.Namespace) -> NoReturn:

    # arguments
    pirfile: str = args.pirfile
    cname: str = args.cname

    if not ASTCParseManager().check_cparser():
        print("*" * 80)
        print("CodeHawk CIL parser not found.")
        print("~" * 80)
        print("Copy CHC/cchcil/parseFile from the (compiled) codehawk ")
        print("repository to the chb/bin/binaries/linux directory in this ")
        print("repository, or ")
        print("set up ConfigLocal.py with another location for parseFile")
        print("*" * 80)
        exit(1)

    cfilename = cname + ".c"
    with open(pirfile, "r") as fp:
        pirjson = json.load(fp)

    lines: List[str] = []
    functions: Dict[str, AST.ASTStmt] = {}
    deserializer = ASTDeserializer(pirjson)
    printglobals = True
    for (faddr, (symtable, dfn)) in deserializer.lifted_functions.items():
        pp = ASTCPrettyPrinter(symtable, annotations=deserializer.annotations)
        lines.append(pp.to_c(dfn, include_globals=printglobals))
        functions[faddr] = dfn
        printglobals = False

    with open(cfilename, "w") as fp:
        fp.write("\n".join(lines))

    parsemanager = ASTCParseManager()
    ifile = parsemanager.preprocess_file_with_gcc(cfilename)
    parsemanager.parse_ifile(ifile)

    for (faddr, dfn) in functions.items():
        fname = faddr.replace("0x", "sub_")
        xpath = os.path.join(cname, "functions")
        xpath = os.path.join(xpath, fname)
        xfile = os.path.join(xpath, cname + "_" + fname + "_cfun.xml")

        if os.path.isfile(xfile):
            try:
                tree = ET.parse(xfile)
                root = tree.getroot()
                rootnode = root.find("function")
            except ET.ParseError as e:
                raise Exception("Error in parsing " + xfile + ": "
                                + str(e.code) + ", " + str(e.position))
        else:
            print("Error: file " + xfile + " not found")
            exit(1)

        if rootnode is None:
            print("Error: No function node found for " + fname)
            exit(1)

        xsbody = rootnode.find("sbody")



    exit(0)
