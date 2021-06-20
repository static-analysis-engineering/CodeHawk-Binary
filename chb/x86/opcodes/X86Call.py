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


from typing import cast, List, Optional, Sequence, Tuple, TYPE_CHECKING

from chb.api.CallTarget import CallTarget, StubTarget, AppTarget
from chb.api.FunctionStub import DllFunction

from chb.app.BDictionary import AsmAddress
from chb.app.InstrXData import InstrXData

from chb.invariants.XXpr import XXpr

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

from chb.x86.X86DictionaryRecord import x86registry
from chb.x86.X86Opcode import X86Opcode
from chb.x86.X86Operand import X86Operand

if TYPE_CHECKING:
    from chb.x86.X86Dictionary import X86Dictionary
    from chb.x86.simulation.X86SimulationState import X86SimulationState


@x86registry.register_tag("call*", X86Opcode)
@x86registry.register_tag("call", X86Opcode)
class X86Call(X86Opcode):
    """CALL tgt.

    args[0]: index of target in x86dictionary
    """

    def __init__(
            self,
            x86d: "X86Dictionary",
            ixval: IndexedTableValue) -> None:
        X86Opcode.__init__(self, x86d, ixval)

    @property
    def tgtoperand(self) -> X86Operand:
        return self.x86d.operand(self.args[0])

    @property
    def operands(self) -> Sequence[X86Operand]:
        return [self.tgtoperand]

    @property
    def is_call(self) -> bool:
        return True

    def has_call_target(self, xdata: InstrXData) -> bool:
        """Returns true if this is a direct call or a resolved indirect call."""

        return xdata.has_call_target()

    def call_target(self, xdata: InstrXData) -> CallTarget:
        return xdata.call_target(self.ixd)

    def is_dll_call(self, xdata: InstrXData) -> bool:
        return (self.has_call_target(xdata)
                and self.call_target(xdata).is_dll_target)

    def is_so_call(self, xdata: InstrXData) -> bool:
        return (self.has_call_target(xdata)
                and self.call_target(xdata).is_so_target)

    def is_app_call(self, xdata: InstrXData) -> bool:
        return (self.has_call_target(xdata)
                and self.call_target(xdata).is_app_target)

    def is_unresolved_call(self, xdata: InstrXData) -> bool:
        return xdata.has_indirect_call_target_exprs()

    def unresolved_call_target_expr(self, xdata: InstrXData) -> XXpr:
        if self.is_unresolved_call(xdata):
            return xdata.xprs[1]
        else:
            raise UF.CHBError(
                "Instruction is not an unresolved call" + str(xdata))

    def has_global_value_unresolved_call_target(self, xdata: InstrXData) -> bool:
        if self.is_unresolved_call(xdata):
            tgtxpr = self.unresolved_call_target_expr(xdata)
            return tgtxpr.is_var and tgtxpr.variable.is_global_value
        else:
            return False

    def target_dll(self, xdata: InstrXData) -> str:
        if self.is_dll_call(xdata):
            tgt = cast(StubTarget, self.call_target(xdata))
            return tgt.dll
        else:
            raise UF.CHBError(
                "Instruction does not have a dll target: " + str(self))

    def dll_target(self, xdata: InstrXData) -> DllFunction:
        if self.is_dll_call(xdata):
            tgt = cast(StubTarget, self.call_target(xdata))
            return cast(DllFunction, tgt.stub)
        else:
            raise UF.CHBError(
                "Instruction does not have a dll target: " + str(self))

    def app_target(self, xdata: InstrXData) -> AsmAddress:
        if self.is_app_call(xdata):
            tgt = cast(AppTarget, self.call_target(xdata))
            return tgt.address
        else:
            raise UF.CHBError(
                "Instruction does not have an application target: " + str(self))

    def arguments(self, xdata: InstrXData) -> List[XXpr]:
        if xdata.has_indirect_call_target_exprs():
            return xdata.xprs[2:]
        elif xdata.has_call_target():
            return xdata.xprs
        else:
            return []

    def annotated_arguments(self, xdata: InstrXData) -> List[Tuple[str, str]]:
        if self.is_dll_call(xdata):
            dlltgt = self.dll_target(xdata)
            if self.app.models.has_dll_function_summary(dlltgt.dll, dlltgt.name):
                summary = self.app.models.dll_function_summary(
                    dlltgt.dll, dlltgt.name)
                params = summary.signature.parameters
                args = self.arguments(xdata)
                if len(params) == len(args):
                    result: List[Tuple[str, str]] = []
                    for (p, x) in zip(params, args):
                        if p.type.is_string():
                            if self.app.stringsxrefs.has_string(str(x)):
                                pvalue = (
                                    '"' + self.app.stringsxrefs.string(str(x)) + '"')
                            else:
                                pvalue = str(x)
                            result.append((p.name, pvalue))
                        elif x.is_constant and x.constant.is_intconst:
                            pvalue = p.represent_value(x.constant.value)
                            result.append((p.name, pvalue))
                        else:
                            result.append((p.name, str(x)))
                    return result
                else:
                    raise UF.CHBError(
                        "Params and args don't match: "
                        + str(len(params))
                        + " vs "
                        + str(len(args)))
            else:
                raise UF.CHBSummaryNotFoundError(dlltgt.dll, dlltgt.name)

        args = self.arguments(xdata)
        return [("args" + str(i + 1), str(x)) for (i, x) in enumerate(args)]

    def annotation(self, xdata: InstrXData) -> str:
        """data format: a:xx... + c

        direct call / resolved indirect call: xprs[0..] arguments
                                              calltarget

        unresolved indirect call: xprs[0] target expression
                                  xprs[1] target expression (simplified)
                                  xprs[2...] arguments
        """

        if xdata.has_indirect_call_target_exprs():
            tgtx = xdata.xprs[1]
            callargs = xdata.xprs[2:]
            return str(tgtx) + "(" + ",".join([str(x) for x in callargs]) + ")"

        elif xdata.has_call_target():
            ctgt = xdata.call_target(self.ixd)
            callargs = xdata.xprs
            return str(ctgt) + "(" + ",".join([str(x) for x in callargs]) + ")"

        else:
            return "call to " + str(self.tgtoperand)
