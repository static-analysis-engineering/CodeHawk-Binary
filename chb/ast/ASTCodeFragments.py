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
"""Code fragments that a patcher may verbatim include into a patch.

A global table of indexed code fragments designated for different purposes.
"""

from typing import Any, Dict, List


class ASTCodeFragment:
    """Contiguous sequence of instructions."""

    def __init__(self, hexstring: str, assembly: List[str]) -> None:
        self._hexstring = hexstring
        self._assembly = assembly

    @property
    def hexstring(self) -> str:
        return self._hexstring

    @property
    def assembly(self) -> List[str]:
        return self._assembly

    def serialize(self) -> Dict[str, Any]:
        return {"hex": self.hexstring, "assembly": self.assembly}

    def __str__(self) -> str:
        return self.hexstring + " (" + "; ".join(self.assembly) + ")"


class ASTCodeFragments:

    def __init__(self) -> None:
        self._codefragments: Dict[int, ASTCodeFragment] = {}

    @property
    def codefragments(self) -> Dict[int, ASTCodeFragment]:
        return self._codefragments

    def codefragment(self, index: int) -> ASTCodeFragment:
        return self.codefragments[index]

    def add_code_fragment(self, hexstring: str, assembly: List[str]) -> int:
        for (index, frag) in self.codefragments.items():
            if frag.hexstring == hexstring:
                return index
        else:
            index = len(self.codefragments)
            self._codefragments[index] = ASTCodeFragment(hexstring, assembly)
            return index

    def is_valid_index(self, index: int) -> bool:
        return index in self.codefragments

    def serialize(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for (index, frag) in sorted(self.codefragments.items()):
            result[str(index)] = frag.serialize()
        return result

    def deserialize(self, serialization: Dict[str, Any]) -> None:
        for (index, fragment) in serialization.items():
            self._codefragments[int(index)] = ASTCodeFragment(fragment["hex"],
                                                              fragment["assembly"])

    def __str__(self) -> str:
        lines: List[str] = []
        for (index, frag) in sorted(self.codefragments.items()):
            lines.append("  " + str(index) + "  " + str(frag))
        return "\n".join(lines)
