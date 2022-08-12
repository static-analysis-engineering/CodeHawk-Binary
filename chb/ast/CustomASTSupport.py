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
"""Class that provides third-party users to introduce local support."""

from typing import Dict, List


arm32_register_sizes: Dict[str, int] = {
    "R0": 32,
    "R1": 32,
    "R2": 32,
    "R3": 32,
    "R4": 32,
    "R5": 32,
    "R6": 32,
    "R7": 32,
    "R8": 32,
    "R9": 32,
    "R10": 32,
    "R11": 32,
    "R12": 32,
    "SP": 32,
    "LR": 32,
    "PC": 32
}


arm32_flags: List[str] = ["C", "N", "V", "Z"]


class CustomASTSupport:

    def __init__(
            self,
            registersizes: Dict[str, int] = arm32_register_sizes,
            flagnames: List[str] = arm32_flags) -> None:
        self._registersizes = registersizes
        self._flagnames = flagnames

    @property
    def register_sizes(self) -> Dict[str, int]:
        return self._registersizes

    @property
    def flagnames(self) -> List[str]:
        return self._flagnames
