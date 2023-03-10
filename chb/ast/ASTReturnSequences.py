# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022-2023  Aarno Labs LLC
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
"""Code fragments that can be used to cleanly return from a function."""

from typing import Dict, List

from chb.ast.ASTCodeFragments import ASTCodeFragments, ASTCodeFragment


class ASTReturnSequences:

    def __init__(self, codefragments: ASTCodeFragments) -> None:
        self._codefragments = codefragments
        self._addressmap: Dict[str, int] = {}  # instruction hex address -> fragment index

    @property
    def codefragments(self) -> ASTCodeFragments:
        return self._codefragments

    @property
    def addressmap(self) -> Dict[str, int]:
        return self._addressmap

    def add_return_sequence(
            self,
            hexstring: str,
            assembly: List[str],
            address: str) -> None:
        index = self.codefragments.add_code_fragment(hexstring, assembly)
        self._addressmap[address] = index

    def has_return_sequence(self, address: str) -> bool:
        return address in self.addressmap

    def get_return_sequence(self, address: str) -> ASTCodeFragment:
        if self.has_return_sequence(address):
            return self.codefragments.codefragment(self.addressmap[address])
        else:
            raise Exception("Address not found in ReturnSequences addressmap")

    def serialize(self) -> Dict[str, str]:
        result: Dict[str, str] = {}
        for (address, index) in sorted(self.addressmap.items()):
            result[address] = str(index)
        return result

    def deserialize(self, serialization: Dict[str, str]) -> None:
        for (addr, str_index) in serialization.items():
            index = int(str_index)
            if not self.codefragments.is_valid_index(index):
                raise Exception("Index %s not found in codefragments" % index)

            self.addressmap[addr] = index

    def __str__(self) -> str:
        lines: List[str] = []
        for (address, index) in sorted(self.addressmap.items()):
            lines.append(address + ": " + str(self.get_return_sequence(address)))
        return "\n".join(lines)
