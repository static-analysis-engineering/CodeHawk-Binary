# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021      Aarno Labs LLC
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
"""Abstract superclass for managing the program counter in a simulation."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Union

import chb.simulation.SimSymbolicValue as SSV

if TYPE_CHECKING:
    from chb.simulation.SimulationState import SimulationState


class SimProgramCounter(ABC):

    def __init__(self) -> None:
        pass

    @property
    @abstractmethod
    def modulename(self) -> str:
        ...

    @property
    @abstractmethod
    def function_address(self) -> str:
        ...

    @abstractmethod
    def set_function_address(self, faddr: str) -> None:
        ...

    @property
    @abstractmethod
    def programcounter(self) -> SSV.SimGlobalAddress:
        ...

    @abstractmethod
    def set_programcounter(self, pc: SSV.SimGlobalAddress) -> None:
        ...

    @abstractmethod
    def set_delayed_programcounter(
            self, pc: Union[SSV.SimGlobalAddress, SSV.SimDynamicLinkSymbol]) -> None:
        ...

    @abstractmethod
    def increment_programcounter(self, simstate: "SimulationState") -> None:
        ...

    @abstractmethod
    def returnaddress(
            self, iaddr: str, simstate: "SimulationState") -> SSV.SimGlobalAddress:
        ...

    def __str__(self) -> str:
        return "not implemented"
