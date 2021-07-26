# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyrigth (c) 2021      Aarno Labs LLC
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

from typing import Dict, List, Mapping, TYPE_CHECKING

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.simulation.SimulationState import SimulationState


class SimSupport:
    """Base class to be subclassed to override network/file operations etc.

    The SimSupport class allows customizing the interaction of the simulator
    with the environment, such as providing network and file input. It also
    can be used to provide better support for format strings and command-line
    arguments.

    Some of the data can simply be provided at initialization. If more logic is
    required, e.g., where a distinction needs to be made in response between
    different calls to the same library function (e.g., the first call to
    select should provide a single filedescriptor, while subsequent calls should
    return multiple, or the first call to accept should succeed, while subsequent
    calls should fail), the respective methods are expected to be overridden by
     a custom class, introduced via dynamic import.
    """

    def __init__(
            self,
            startaddr: str,
            stepcount: int = 100,
            optoptaddr: SV.SimValue = SV.simZero,
            optargaddr: SV.SimValue = SV.simZero,
            patched_globals: Dict[str, str] = {},
            environment_variables: Dict[str, str] = {},
            diskfilenames: Dict[str, str] = {},
            forkchoices: Dict[str, int] = {}) -> None:
        self._startaddr = startaddr
        self._stepcount = stepcount
        self._optoptaddr = optoptaddr  # address of cli
        self._optargaddr = optargaddr  # address where argument is saved by cli
        self._patched_globals = patched_globals
        self._environment_variables = environment_variables
        self._diskfilenames = diskfilenames
        self._forkchoices = forkchoices

    @property
    def startaddr(self) -> str:
        """Return the starting address of the simulation (in main executable)."""

        return self._startaddr

    @property
    def stepcount(self) -> int:
        """Return the number of simulation steps to execute."""

        return self._stepcount

    @property
    def optoptaddr(self) -> SV.SimValue:
        return self._optoptaddr

    @property
    def optargaddr(self) -> SV.SimValue:
        return self._optargaddr

    @property
    def patched_globals(self) -> Mapping[str, str]:
        return self._patched_globals

    @property
    def environment_variables(self) -> Mapping[str, str]:
        """Return values of environment variables."""

        return self._environment_variables

    @property
    def diskfilenames(self) -> Dict[str, str]:
        return self._diskfilenames

    @property
    def forkchoices(self) -> Dict[str, int]:
        return self._forkchoices

    def do_initialization(self, simstate: "SimulationState") -> None:
        pass

    def has_network_input(self, iaddr: str) -> bool:
        """Return true if there is network input configured for this address."""
        return False

    def network_input(
            self,
            iaddr: str,
            simstate: "SimulationState",
            size: int) -> str:
        """Return network input."""
        raise UF.CHBError("No network input configured for address " + iaddr)

    def read_input(
            self,
            iaddr: str,
            filedescriptor: int,
            buffer: SSV.SimAddress,
            buffersize: int) -> List[int]:
        """Return bytes that are read in at a read call at this address."""
        return []

    def supplemental_library_stubs(self) -> Dict[str, str]:
        """Return mapping of hex-addresses to names of library functions.

        Intended to replace library functions that are not captured correctly.
        """
        return {}

    def branch_decision(self, iaddr: str, simstate: "SimulationState") -> bool:
        """Return True/False to indicate which branch to take."""
        return False
