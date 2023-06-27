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

from typing import Any, Dict, List, NoReturn, Optional

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree
from chb.ast.ASTDeserializer import ASTDeserializer
import chb.ast.ASTNode as AST
from chb.ast.ASTViewer import ASTViewer
import chb.ast.astdotutil as DU


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
            + "\nSpecify either name or address")
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
        faddr: str, level: str, pirjson: Dict[str, Any]) -> DU.ASTDotGraph:

    deserializer = ASTDeserializer(pirjson)
    (globaltable, dfns) = deserializer.deserialize()
    for dfn in dfns:
        if dfn.astree.faddr == faddr:
            viewer = ASTViewer(faddr, dfn.astree)
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

    with open(pirfile, "r") as fp:
        pirjson = json.load(fp)    

    faddr = get_function_addr(pirjson, function)
    g = view_ast_function(faddr, level, pirjson)
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
    

    
    
