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

from typing import Dict, List, Optional, Tuple


# ARM32 regular registers
arm32_register_sizes: Dict[str, int] = {
    "R" + str(i): 32 for i in range(0, 13)}
arm32_register_sizes["SP"] = 32   # stack pointer
arm32_register_sizes["LR"] = 32   # link register
arm32_register_sizes["PC"] = 32   # program counter

# ARM32 double registers
arm32_register_sizes["R2_R3"] =  64

# ARM32 floating point / adv simd registers
arm_fp_sp_register_sizes: Dict[str, int] = {
    "S" + str(i): 32 for i in range(0, 31)}

arm_fp_dp_register_sizes: Dict[str, int] = {
    "D" + str(i): 64 for i in range(0, 31)}

arm32_register_sizes["FPSCR"] = 32  # floating point status control register

# ARM32 flags
arm32_flags: List[str] = ["C", "N", "V", "Z"]


# Power32 registers
pwr32_register_sizes: Dict[str, int] = {
    "r" + str(i): 32 for i in range(0, 32)}
pwr32_register_sizes["lr"] = 32
pwr32_register_sizes["ctr"] = 32
pwr32_register_sizes["cr"] = 32

# Power32 condition register fields
pwr32_crf_sizes: Dict[str, int] = {
    "cr" + str(i): 4 for i in range(0, 8)}


all_register_sizes = {
    **arm32_register_sizes,
    **arm_fp_sp_register_sizes,
    **arm_fp_dp_register_sizes,
    **pwr32_register_sizes,
    **pwr32_crf_sizes}


class CustomASTSupport:

    def __init__(
            self,
            registersizes: Dict[str, int] = all_register_sizes,
            flagnames: List[str] = arm32_flags) -> None:
        self._registersizes = registersizes
        self._flagnames = flagnames

    @property
    def register_sizes(self) -> Dict[str, int]:
        return self._registersizes

    @property
    def flagnames(self) -> List[str]:
        return self._flagnames

    @property
    def toolname_and_version(self) -> Optional[Tuple[str, str]]:
        return None
