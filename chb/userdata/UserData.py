# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
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

from typing import Dict, List, Optional, Sequence

import xml.etree.ElementTree as ET

from chb.userdata.UserXorEncoding import UserXorEncoding
from chb.userdata.UserCallTarget import UserCallTarget
from chb.userdata.UserCfNop import UserCfNop
from chb.userdata.UserStackAdjustment import UserStackAdjustment
from chb.userdata.UserFunctionNames import UserFunctionNames
from chb.userdata.SymbolicAddresses import SymbolicAddresses

import chb.util.fileutil as UF


class UserData:

    def __init__(self, xnode: ET.Element) -> None:
        self.xnode = xnode
        self._symbolicaddresses: Optional[SymbolicAddresses] = None
        self._functionnames: Optional[UserFunctionNames] = None
        self._calltargets: List[UserCallTarget] = []
        self._xorencodings: List[UserXorEncoding] = []
        self._cfnops: List[UserCfNop] = []
        self._stackadjustments: List[UserStackAdjustment] = []

    def has_symbolic_addresses(self) -> bool:
        return "symbolic-addresses" in self.xnode.attrib

    @property
    def symbolicaddresses(self) -> SymbolicAddresses:
        if self._symbolicaddresses is None:
            if self.has_symbolic_addresses():
                xsymaddresses = self.xnode.find('symbolic-addresses')
                if xsymaddresses is not None:
                    self._symbolicaddresses = SymbolicAddresses(xsymaddresses)
                else:
                    raise UF.CHBError("No symbolic addresses found in userdata")
            else:
                raise UF.CHBError("No symbolic addresses present in userdata")
        return self._symbolicaddresses

    def has_symbolic_address(self, addr: str) -> bool:
        if self.has_symbolic_addresses():
            return self.symbolicaddresses.has_symbolic_address(addr)
        else:
            return False

    def has_function_names(self) -> bool:
        return "function-names" in self.xnode.attrib

    @property
    def functionnames(self) -> UserFunctionNames:
        if self._functionnames is None:
            if self.has_function_names():
                xfunctionnames = self.xnode.find('function-names')
                if xfunctionnames is not None:
                    self._functionnames = UserFunctionNames(xfunctionnames)
                else:
                    raise UF.CHBError("No function names found in userdata")
            else:
                raise UF.CHBError("No function names present in userdata")
        return self._functionnames

    def get_call_targets(self) -> Sequence[UserCallTarget]:
        if len(self._calltargets) == 0:
            xtgts = self.xnode.find('call-targets')
            if xtgts is not None:
                for xtgt in xtgts.findall("tgt"):
                    self._calltargets.append(UserCallTarget(xtgt))
        return self._calltargets

    def get_xor_encodings(self) -> Sequence[UserXorEncoding]:
        if len(self._xorencodings) == 0:
            xencs = self.xnode.find("encodings")
            if xencs is not None:
                for xenc in xencs.findall("encoding"):
                    self._xorencodings.append(UserXorEncoding(xenc))
        return self._xorencodings

    def get_cfnops(self) -> Sequence[UserCfNop]:
        if len(self._cfnops) == 0:
            xnops = self.xnode.find('cfnops')
            if xnops is not None:
                for xnop in xnops.findall("nop"):
                    self._cfnops.append(UserCfNop(xnop))
        return self._cfnops

    def get_stack_adjustments(self) -> Sequence[UserStackAdjustment]:
        if len(self._stackadjustments) == 0:
            xadjs = self.xnode.find('esp-adjustments')
            if xadjs is not None:
                for xadj in xadjs.findall("esp-adj"):
                    self._stackadjustments.append(UserStackAdjustment(xadj))
        return self._stackadjustments

    def get_cfnop_summary(self) -> Dict[str, int]:
        result: Dict[str, int] = {}
        for nop in self.get_cfnops():
            desc = nop.description
            result.setdefault(desc, 0)
            result[desc] += 1
        return result

    def __str__(self) -> str:
        lines: List[str] = []
        calltargets = self.get_call_targets()
        xorencodings = self.get_xor_encodings()
        cfnops = self.get_cfnops()
        stackadjustments = self.get_stack_adjustments()
        if len(calltargets) > 0:
            lines.append('Call targets')
            for c in calltargets:
                lines.append('  ' + str(c))
        if len(xorencodings) > 0:
            lines.append('Xor encodings')
            for x in xorencodings:
                lines.append('  ' + str(x))
        if len(cfnops) > 0:
            lines.append('Control flow nops')
            for cfnop in cfnops:
                lines.append('  ' + str(cfnop))
        if len(stackadjustments) > 0:
            for s in stackadjustments:
                lines.append('  ' + str(s))
        return '\n'.join(lines)
