# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021      Aarno Labs
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
"""Basic class for user-supplied simulation information."""

from typing import Callable, Dict, List, Mapping, Optional, Tuple, TYPE_CHECKING

from chb.simulation.SimSupport import SimSupport
import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.mips.MIPSAccess import MIPSAccess
    from chb.mips.simulation.MIPSimStubs import MIPSimStub
    from chb.mips.simulation.MIPSimulationState import MIPSimulationState


class MIPSimSupport(SimSupport):

    def __init__(
            self,
            startaddr: str,
            stepcount: int = 100,
            optoptaddr: SV.SimValue = SV.simZero,
            optargaddr: SV.SimValue = SV.simZero,
            patched_globals: Dict[str, str] = {},
            diskfilenames: Dict[str, str] = {},
            forkchoices: Dict[str, int] = {},
            enable_file_operations: bool = False) -> None:
        SimSupport.__init__(
            self,
            startaddr,
            stepcount=stepcount,
            optoptaddr=optoptaddr,
            optargaddr=optargaddr,
            patched_globals=patched_globals,
            diskfilenames=diskfilenames,
            forkchoices=forkchoices)
        self._enable_file_operations = enable_file_operations

    def enable_file_operations(self) -> bool:
        return self._enable_file_operations

    def get_target_address(self) -> Optional[str]:
        """If relevant, return a hex address that must be reached."""
        return None

    def cwd(self) -> str:
        """Return current working directory."""
        return "/"

    def substitute_formatstring(
            self,
            stub: "MIPSimStub",
            iaddr: str,
            simstate: "MIPSimulationState",
            fmtstring: str) -> Optional[Tuple[str, List[str]]]:
        return None

    def get_lib_stubs(self) -> Mapping[str, Callable[["MIPSAccess"], "MIPSimStub"]]:
        """Return dictionary of name-stubinvocation pairs of imported functions.

        Can include both stubs for library functions from libraries other than
        libc, or stubs of libc functions that override the default libc stubs.
        """
        return {}

    def get_app_stubs(self) -> Mapping[
            str, Callable[["MIPSAccess"], "MIPSimStub"]]:
        """Return dictionary of hexaddr-stubinvocation pairs of application functions.

        Intended to stub out application functions that take a lot of execution
        steps without much relevant modification of state.
        """
        return {}

    def check_target_path(self, iaddr: str) -> Optional[List[str]]:
        """Provide a target path that must be followed."""
        return None

    def get_ctype_toupper(self) -> Optional[str]:
        """Return the global access address for __ctype_toupper (as encountered statically)."""
        return None

    def get_ctype_b(self) -> Optional[str]:
        """Return the global access address for __ctype_b (as encountered statically)."""
        return None
