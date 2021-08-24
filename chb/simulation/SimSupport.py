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

from typing import Dict, List, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING, Union

import chb.simulation.SimSymbolicValue as SSV
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF

if TYPE_CHECKING:
    from chb.app.AppAccess import AppAccess
    from chb.simulation.SimStub import SimStub
    from chb.simulation.SimulationState import SimulationState


class SimCallIntercept:
    """Base class to intercept function calls."""

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def do_before(self, iaddr: str, simstate: "SimulationState") -> None:
        pass

    def do_after(self, iaddr: str, simstate: "SimulationState") -> None:
        pass

    def do_replace(self, iaddr: str, simstate: "SimulationState") -> bool:
        return False

    def replace(self, iaddr: str, simstate: "SimulationState") -> None:
        pass


class SimInstructionIntercept:
    """Base class to intercept arbitrary instructions."""

    def __init__(self, modulename: str, iaddr: str) -> None:
        self._modulename = modulename
        self._iaddr = iaddr

    @property
    def modulename(self) -> str:
        return self._modulename

    @property
    def iaddr(self) -> str:
        return self._iaddr

    def do_before(self, iaddr: str, simstate: "SimulationState") -> None:
        pass

    def do_after(self, iaddr: str, simstate: "SimulationState") -> None:
        pass

    def do_replace(self, iaddr: str, simstate: "SimulationState") -> bool:
        return False

    def replace(self, iaddr: str, simstate: "SimulationState") -> None:
        pass


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
            stepcount: int = 100,
            optoptaddr: SV.SimValue = SV.simZero,
            optargaddr: SV.SimValue = SV.simZero,
            patched_globals: Dict[str, str] = {},
            environment_variables: Dict[str, str] = {},
            environmentptr_address: Optional[SSV.SimGlobalAddress] = None,
            diskfilenames: Dict[str, str] = {},
            forkchoices: Dict[str, int] = {},
            file_operations_enabled: bool = True) -> None:
        self._stepcount = stepcount
        self._optoptaddr = optoptaddr  # address of cli
        self._optargaddr = optargaddr  # address where argument is saved by cli
        self._patched_globals = patched_globals
        self._environment_variables = environment_variables
        self._environmentptr_address = environmentptr_address
        self._forkchoices = forkchoices
        self._file_operations_enabled = file_operations_enabled
        self._callintercepts: Dict[str, SimCallIntercept] = {}
        self._instructionintercepts: Dict[str, Dict[str, SimInstructionIntercept]]

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
    def file_operations_enabled(self) -> bool:
        return self._file_operations_enabled

    # Environment variables

    @property
    def environmentptr_address(self) -> SSV.SimGlobalAddress:
        """Return global variable that holds the pointer to the environment variables."""
        if self._environmentptr_address is not None:
            return self._environmentptr_address
        else:
            raise UF.CHBError(
                "Environment pointer address has not been set")

    @property
    def environment_variables(self) -> Mapping[str, str]:
        return self._environment_variables

    def has_environmentptr_address(self) -> bool:
        return self._environmentptr_address is not None

    def has_environment_variable(self, name: str) -> bool:
        return name in self.environment_variables

    def get_environment_variable(self, name) -> str:
        if name in self.environment_variables:
            return self.environment_variables[name]
        else:
            raise UF.CHBError(
                "Value for environment variable " + name + " not found")

    def set_environment_variable(self, vname: str, vval: str) -> None:
        self._environment_variables[vname] = vval

    @property
    def call_intercepts(self) -> Mapping[str, SimCallIntercept]:
        return self._callintercepts

    def has_call_intercept(self, name: str) -> bool:
        return name in self.call_intercepts

    def call_intercept(self, name: str) -> SimCallIntercept:
        if self.has_call_intercept:
            return self.call_intercepts[name]
        else:
            raise UF.CHBError("No call intercept found for " + name)

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

    def cwd(self) -> str:
        """Return current working directory."""

        raise UF.CHBError("cwd: not yet implemented")

    def substitute_formatstring(
            self,
            stub: "SimStub",
            iaddr: str,
            simstate: "SimulationState",
            fmtstring: str) -> Optional[Tuple[str, List[str]]]:
        return None

    # Shared memory support

    def semaphore_semctl(
            self,
            iaddr: str,
            simstate: "SimulationState",
            semid: int,
            semnum: int,
            cmd: int) -> int:
        """int semctl(int semid, int semnum, int cmd, ...);"""

        return -1

    def semaphore_semget(
            self,
            iaddr: str,
            simstate: "SimulationState",
            key: int,
            nsems: int,
            semflg: int) -> int:
        """int semget(key_t key, int nsems, int semflg);"""

        return -1

    def semaphore_semop(
            self,
            iaddr: str,
            simstate: "SimulationState",
            semid: int,
            sembuf: SSV.SimAddress,
            nsops: int) -> int:
        """int semop(int semid, struct sembuf *sops, size_t nsops);"""

        return -1

    def sharedmem_shmat(
            self,
            iaddr: str,
            simstate: "SimulationState",
            shmid: int,
            shmaddr: SSV.SimGlobalAddress,
            shmflg: int) -> SSV.SimGlobalAddress:
        """void *shmat(int shmid, const void *shmaddr, int shmflg);"""

        return SSV.mk_undefined_global_address("shared:" + str(shmid))

    def sharedmem_shmctl(
            self,
            iaddr: str,
            simstate: "SimulationState",
            shmid: int,
            cmd: int,
            shmid_ds: SSV.SimAddress) -> int:
        """int shmctl(int shmid, int cmd, struct shmid_ds *buf);"""

        return -1

    def sharedmem_shmdt(
            self,
            iaddr: str,
            simstate: "SimulationState",
            shmaddr: SSV.SimGlobalAddress) -> int:
        """int shmdt(const void *shmaddr);"""

        return -1

    def sharedmem_shmget(
            self,
            iaddr: str,
            simstate: "SimulationState",
            key: int,
            size: int,
            shmflg: int) -> int:
        """int shmget(key_t key, size_t size, int shmflg);"""

        return -1
