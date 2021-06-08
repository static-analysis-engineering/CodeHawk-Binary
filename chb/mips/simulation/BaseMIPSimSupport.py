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

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.mips.MIPSAccess import MIPSAccess
    from chb.mips.simulation.MIPSimStubs import MIPSimStub
    from chb.mips.simulation.MIPSimulationState import MIPSimulationState


class BaseMIPSimSupport:

    def __init__(
            self,
            startaddr: str,
            enable_file_operations: bool = False) -> None:
        """Hex address of starting point of the simulation."""
        self._startaddr = startaddr
        self._optoptaddr = SV.simZero
        # address where argument is saved by command-line processor
        self._optargaddr = SV.simZero
        self._enable_file_operations = enable_file_operations
        self.diskfilenames: Dict[str, str] = {}
        self.forkchoices: Dict[str, int] = {}
        self.argumentrecorder = None

    @property
    def startaddr(self) -> str:
        return self._startaddr

    @property
    def optoptaddr(self) -> SV.SimValue:
        return self._optoptaddr

    @property
    def optargaddr(self) -> SV.SimValue:
        return self._optargaddr

    def enable_file_operations(self) -> bool:
        return self._enable_file_operations

    def do_initialization(self, simstate: "MIPSimulationState") -> None:
        pass

    def get_target_address(self) -> Optional[str]:
        """If relevant, return a hex address that must be reached."""
        return None

    def get_step_count(self) -> int:
        """Return the number of instructions to be simulated."""
        return 1000

    def get_environment(self) -> Mapping[str, str]:
        """Return dictionary of key-value pairs of environment variables."""
        return {}

    def get_cwd(self) -> str:
        """Return current working directory."""
        return "/"

    def has_network_input(self, iaddr: str) -> bool:
        """Return true if there is network input configured for this address."""
        return False

    def get_network_input(
            self,
            iaddr: str,
            simstate: "MIPSimulationState",
            size: int) -> str:
        """Return network input."""
        raise UF.CHBError('No network input configured for address ' + iaddr)

    def get_read_input(
            self,
            iaddr: str,
            filedescriptor: int,
            buffer: SSV.SimAddress,
            buffersize: int) -> List[int]:
        """Return bytes that are read in at a read call at this address."""
        return []

    def substitute_formatstring(
            self,
            stub: "MIPSimStub",
            iaddr: str,
            simstate: "MIPSimulationState",
            fmtstring: str) -> Optional[Tuple[str, List[str]]]:
        return None

    def get_supplemental_library_stubs(self) -> Dict[str, str]:
        """Return dictionary of hex-address,name pairs of library functions.

        Sometimes library functions are not captured correctly.
        """
        return {}

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

    def get_patched_globals(self) -> Mapping[str, str]:
        """Return dictionary of hexaddress,hexvalue pairs of global addresses
        and values."""
        return {}

    def get_branch_decision(
            self, iaddr: str, simstate: "MIPSimulationState") -> bool:
        """Return True/False to indicate which branch to take."""
        return False

    def check_target_path(self, iaddr: str) -> Optional[List[str]]:
        """Provide a target path that must be followed."""
        return None

    def get_ctype_toupper(self) -> Optional[str]:
        """Return the global access address for __ctype_toupper (as encountered statically)."""
        return None

    def get_ctype_b(self) -> Optional[str]:
        """Return the global access address for __ctype_b (as encountered statically)."""
        return None
