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
"""Provenance data structure to provide ast meta data."""

from typing import Dict, List, Mapping, TYPE_CHECKING, Union


class ASTProvenance:

    def __init__(self) -> None:
        self._instruction_mapping: Dict[int, List[int]] = {}
        self._expression_mapping: Dict[int, int] = {}
        self._lval_mapping: Dict[int, int] = {}
        self._reaching_definitions: Dict[int, List[int]] = {}
        self._flag_reaching_definitions: Dict[int, List[int]] = {}
        self._definitions_used: Dict[int, List[int]] = {}

    @property
    def instruction_mapping(self) -> Mapping[int, List[int]]:
        return self._instruction_mapping

    @property
    def expression_mapping(self) -> Mapping[int, int]:
        return self._expression_mapping

    @property
    def lval_mapping(self) -> Mapping[int, int]:
        return self._lval_mapping

    @property
    def reaching_definitions(self) -> Mapping[int, List[int]]:
        return self._reaching_definitions

    @property
    def flag_reaching_definitions(self) -> Mapping[int, List[int]]:
        return self._flag_reaching_definitions

    @property
    def definitions_used(self) -> Mapping[int, List[int]]:
        return self._definitions_used

    def add_instruction_mapping(self, hl_instrid: int, ll_instrid: int) -> None:
        self._instruction_mapping.setdefault(hl_instrid, [])
        if ll_instrid not in self.instruction_mapping[hl_instrid]:
            self._instruction_mapping[hl_instrid].append(ll_instrid)

    def add_expression_mapping(self, hl_exprid: int, ll_exprid: int) -> None:
        self._expression_mapping[hl_exprid] = ll_exprid

    def add_lval_mapping(self, hl_lvalid: int, ll_lvalid: int) -> None:
        self._lval_mapping[hl_lvalid] = ll_lvalid

    def add_reaching_definitions(self, exprid: int, instrids: List[int]) -> None:
        self._reaching_definitions.setdefault(exprid, [])
        for instrid in instrids:
            if instrid not in self.reaching_definitions[exprid]:
                self._reaching_definitions[exprid].append(instrid)

    def add_flag_reaching_definitions(
            self, exprid: int, instrids: List[int]) -> None:
        self._flag_reaching_definitions.setdefault(exprid, [])
        for instrid in instrids:
            if instrid not in self.flag_reaching_definitions[exprid]:
                self._flag_reaching_definitions[exprid].append(instrid)

    def add_definitions_used(self, lvalid: int, instrids: List[int]) -> None:
        self._definitions_used.setdefault(lvalid, [])
        for instrid in instrids:
            if instrid not in self.definitions_used[lvalid]:
                self._definitions_used[lvalid].append(instrid)

    def serialize(self) -> Mapping[str, Mapping[int, Union[int, List[int]]]]:
        result: Dict[str, Mapping[int, Union[int, List[int]]]] = {}
        result["instruction-mapping"] = self.instruction_mapping
        result["expression-mapping"] = self.expression_mapping
        result["lval-mapping"] = self.lval_mapping
        result["reaching-definitions"] = self.reaching_definitions
        result["flag-reaching-definitions"] = self.flag_reaching_definitions
        result["definitions-used"] = self.definitions_used
        return result
