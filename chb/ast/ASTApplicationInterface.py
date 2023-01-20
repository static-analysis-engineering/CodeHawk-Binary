# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2023  Aarno Labs, LLC
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
"""Main interface to the AST library."""

from datetime import datetime

from typing import Any, Dict, List

from chb.ast.AbstractSyntaxTree import AbstractSyntaxTree
from chb.ast.ASTCodeFragments import ASTCodeFragments
from chb.ast.ASTCPrettyPrinter import ASTCPrettyPrinter
from chb.ast.ASTDeserializer import ASTDeserializer
from chb.ast.ASTFunction import ASTFunction
from chb.ast.ASTNode import ASTStmt, ASTVarInfo
from chb.ast.ASTSerializer import ASTSerializer
from chb.ast.ASTStorageChecker import ASTStorageChecker
from chb.ast.ASTSymbolTable import ASTGlobalSymbolTable, ASTLocalSymbolTable
from chb.ast.CustomASTSupport import CustomASTSupport


pirversion: str = "0.1.0-20230119"


class ASTApplicationInterface:

    def __init__(
            self,
            support: CustomASTSupport = CustomASTSupport()) -> None:
        self._support = support
        self._globalsymboltable = ASTGlobalSymbolTable()
        self._codefragments = ASTCodeFragments()
        self._fnsdata: List[Dict[str, Any]] = []

    @property
    def support(self) -> CustomASTSupport:
        return self._support

    @property
    def globalsymboltable(self) -> ASTGlobalSymbolTable:
        return self._globalsymboltable

    @property
    def codefragments(self) -> ASTCodeFragments:
        return self._codefragments

    def add_function_ast(
            self,
            astree: AbstractSyntaxTree,
            asts: List[ASTStmt],
            verbose: bool = False) -> None:
        """Add function with its abstract syntax tree object and list of asts.

        There should be at least two asts, there may be more. It is assumed that
        the first ast is the high-level ast, and the last ast is the low-level
        ast.
        """

        localsymboltable = astree.symboltable
        if len(asts) < 2:
            raise Exception(
                "Found only "
                + str(len(asts))
                + " asts. Expected at least two asts")
        lifted_ast = asts[0]
        low_level_ast = asts[-1]

        if verbose:
            print("\n")
            pp = ASTCPrettyPrinter(localsymboltable)
            print("Lifted AST")
            print("----------")
            print(pp.to_c(lifted_ast))
            print("\nLow-level AST")
            print("--------------")
            print(pp.to_c(low_level_ast))

        if verbose:
            print("\nCheck Storage")
            print("---------------")
            storagechecker = ASTStorageChecker(astree.storage)
            report = storagechecker.check_stmt(lifted_ast)

            print("\nHigh-level representation")
            print(report)

            report = storagechecker.check_stmt(low_level_ast)
            print("\nLow-level representation")
            print(report)

        fndata: Dict[str, Any] = {}
        serializer = astree.serializer

        localsymboltable.serialize(serializer)
        protoindex = localsymboltable.serialize_function_prototype(serializer)
        ast_startindices = [serializer.index_stmt(ast) for ast in asts]
        astnodes = serializer.records()

        fndata["name"] = astree.fname
        fndata["va"] = astree.faddr
        fndata["prototype"] = protoindex
        fndata["ast"] = {}
        fndata["ast"]["nodes"] = astnodes
        fndata["ast"]["ast-startnodes"] = ast_startindices
        fndata["spans"] = astree.spans
        fndata["provenance"] = astree.provenance.serialize()
        fndata["available-expressions"] = astree.available_expressions
        fndata["storage"] = astree.storage_records()
        fndata["return-sequences"] = astree.serialize_return_sequences()

        self._fnsdata.append(fndata)

    def serialize(self, verbose: bool = False) -> Dict[str, Any]:
        globalserializer = ASTSerializer()
        self.globalsymboltable.serialize(globalserializer)

        ast_output: Dict[str, Any] = {}

        if self.support.toolname_and_version is not None:
            (toolname, toolversion) = self.support.toolname_and_version
            ast_output["created-by"] = {}
            ast_output["created-by"]["tool-name"] = toolname
            ast_output["created-by"]["tool-version"] = toolversion
            ast_output["created-by"]["time"] = str(datetime.now())
        ast_output["pir-version"] = pirversion
        ast_output["global-symbol-table"] = globalserializer.records()
        ast_output["codefragments"] = self.codefragments.serialize()
        ast_output["functions"] = self._fnsdata

        if verbose:

            print("\nDeserialized cfg-ast output")
            print("-----------------------")
            deserializer = ASTDeserializer(ast_output)
            for (symtable, ast) in deserializer.functions.values():
                pp = ASTCPrettyPrinter(symtable, annotations=deserializer.annotations)
                print("\n")
                print(pp.to_c(ast))

            print("\nDeserialized lifted ast output")
            print("-----------------------")
            deserializer = ASTDeserializer(ast_output)
            for (symtable, ast) in deserializer.lifted_functions.values():
                pp = ASTCPrettyPrinter(symtable, annotations=deserializer.annotations)
                print("\n")
                print(pp.to_c(ast))

            print("\nCheck expression node parentage")
            deserializer.check_expr_node_parentage()

        return ast_output
