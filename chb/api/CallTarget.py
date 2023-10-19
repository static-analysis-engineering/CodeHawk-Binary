# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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
"""Target of a call instruction.

Represents call_target_t from bchlib/bCHLibTypes:

(* Call target types:
   StubTarget: dynamically linked function external to the executable
   StaticStubTarget:
       library function with summary statically linked in the executable
   AppTarget: application function with address
   InlinedAppTarget: application function with address that is inlined
   WrappedTarget:
      application function that wraps a call to another function
        a: address of wrapper function;
        fapi: function api of wrapper function;
        tgt: call target of wrapped function
        mapping: maps wrapped function arguments to wrapper function arguments
                 and constants provided by the wrapper function internally
   VirtualTarget: virtual function specified in class vtable
   IndirectTarget:
      indirect call on external variable (global variable, function argument,
      or return value)
   UnknownTarget: target of indirect call that has not been resolved yet
*)
                                                    tags[0]   tags    args
type call_target_t =
  | StubTarget of function_stub_t                   "stub"      1       1
  | StaticStubTarget of                            "sstub"      1       2
      doubleword_int * function_stub_t
  | AppTarget of doubleword_int                      "app"      1       1
  | InlinedAppTarget of doubleword_int * string      "inl"      1       2
  | WrappedTarget of                                "wrap"      1   3+length(pars)
      doubleword_int
      * function_api_t
      * call_target_t
      * (api_parameter_t * bterm_t) list
  | VirtualTarget of function_api_t                    "v"      1        1
  | IndirectTarget of                                  "i"      1   1+length(tgts)
      bterm_t * call_target_t list
  | CallbackTableTarget of string * int                "cb"     1        2
  | UnknownTarget                                      "u"      1        0

"""

from typing import cast, List, TYPE_CHECKING

from chb.api.FunctionStub import FunctionStub, DllFunction
from chb.api.InterfaceDictionaryRecord import (
    InterfaceDictionaryRecord, apiregistry)
from chb.app.BDictionary import AsmAddress

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.api.InterfaceDictionary


class CallTarget(InterfaceDictionaryRecord):

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, d, ixval)

    @property
    def is_dll_target(self) -> bool:
        return False

    @property
    def is_so_target(self) -> bool:
        return False

    @property
    def is_syscall_target(self) -> bool:
        return False

    @property
    def is_app_target(self) -> bool:
        return False

    @property
    def is_static_stub_target(self) -> bool:
        return False

    @property
    def is_indirect(self) -> bool:
        return False

    @property
    def is_call_back_table(self) -> bool:
        return False

    @property
    def is_unknown(self) -> bool:
        return False

    @property
    def name(self) -> str:
        return str(self)

    def __str__(self) -> str:
        return "call-target:" + self.tags[0]


@apiregistry.register_tag("stub", CallTarget)
class StubTarget(CallTarget):
    """Call to a library function.

    args[0]: index of function stub in interface dictionary
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IndexedTableValue) -> None:
        CallTarget.__init__(self, d, ixval)

    @property
    def stub(self) -> FunctionStub:
        return self.id.function_stub(self.args[0])

    @property
    def dll(self) -> str:
        if self.is_dll_target:
            dllstub = cast(DllFunction, self.stub)
            return dllstub.dll
        else:
            raise UF.CHBError("Target is not a dll target: " + str(self))

    @property
    def name(self) -> str:
        return self.stub.name

    @property
    def is_dll_target(self) -> bool:
        return self.stub.is_dll_stub

    @property
    def is_so_target(self) -> bool:
        return self.stub.is_so_stub

    @property
    def is_syscall_target(self) -> bool:
        return self.stub.is_syscall_stub

    def __str__(self) -> str:
        return str(self.stub)


@apiregistry.register_tag("sstub", CallTarget)
class StaticStubTarget(CallTarget):
    """Call to a statically linked library function.

    args[0]: index of application function address in bdictionary
    args[1]: index of function stub in interface dictionary
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IndexedTableValue) -> None:
        CallTarget.__init__(self, d, ixval)

    @property
    def address(self) -> AsmAddress:
        return self.bd.address(self.args[0])

    @property
    def stub(self) -> FunctionStub:
        return self.id.function_stub(self.args[1])

    @property
    def is_static_stub_target(self) -> bool:
        return True

    @property
    def is_so_target(self) -> bool:
        return self.stub.is_so_stub

    @property
    def name(self) -> str:
        return self.stub.name

    def __str__(self) -> str:
        return str(self.stub) + '@' + str(self.address)


@apiregistry.register_tag("app", CallTarget)
class AppTarget(CallTarget):
    """Call to application function.

    args[0]: index of application function address in bdictionary
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IndexedTableValue) -> None:
        CallTarget.__init__(self, d, ixval)

    @property
    def address(self) -> AsmAddress:
        return self.bd.address(self.args[0])

    def has_tgt_name(self) -> bool:
        return self.app.has_function_name(str(self.address))

    def tgt_name(self) -> str:
        if self.has_tgt_name():
            return self.app.function_name(str(self.address))
        else:
            raise UF.CHBError(
                "Application target "
                + str(self.address)
                + " does not have a name")

    @property
    def is_app_target(self) -> bool:
        return True

    @property
    def name(self) -> str:
        addr = str(self.address)
        if self.app.has_function_name(addr):
            return self.app.function_name(addr)
        else:
            return "sub_" + addr[2:]

    def __str__(self) -> str:
        return self.name


@apiregistry.register_tag("inl", CallTarget)
class InlinedAppTarget(CallTarget):
    """Application function call that has been inlined.

    args[0]: index of address of application function in bdictionary
    args[1]: index of name of application function in bdictionary
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IndexedTableValue) -> None:
        CallTarget.__init__(self, d, ixval)

    @property
    def address(self) -> AsmAddress:
        return self.bd.address(self.args[0])

    @property
    def name(self) -> str:
        return self.bd.string(self.args[1])

    def __str__(self) -> str:
        return 'Inl:' + self.name


@apiregistry.register_tag("wrap", CallTarget)
class WrappedTarget(CallTarget):
    """Wrapped call to application function

    args[0]: index of address of application function in bdictionary
    args[1]: index of function api in interface dictionary
    args[2]: index of call target in interface dictionary
    args[3..]: indices of api parameters in interface dictionary
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IndexedTableValue) -> None:
        CallTarget.__init__(self, d, ixval)


@apiregistry.register_tag("v", CallTarget)
class VirtualTarget(CallTarget):
    """Virtual call that is not resolved.

    args[0]: index of function api in interface dictionary
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IndexedTableValue) -> None:
        CallTarget.__init__(self, d, ixval)


@apiregistry.register_tag("i", CallTarget)
class IndirectTarget(CallTarget):
    """Indirect call with multiple potential targets.

    args[0]: index of call-target expression in interface dictionary
    args[1..]: indices of call targets in interface dictionary
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IndexedTableValue) -> None:
        CallTarget.__init__(self, d, ixval)

    @property
    def is_indirect(self) -> bool:
        return True

    def has_multiple_targets(self) -> bool:
        return len(self.args) > 2

    @property
    def targets(self) -> List["CallTarget"]:
        return [self.id.call_target(i) for i in self.args[1:]]


@apiregistry.register_tag("cb", CallTarget)
class CallbackTableTarget(CallTarget):
    """Target is dispatched on a function pointer in a list of structs."""

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IndexedTableValue) -> None:
        CallTarget.__init__(self, d, ixval)

    @property
    def is_call_back_table(self) -> bool:
        return True

    @property
    def address(self) -> str:
        return str(self.bd.address(self.args[0]))

    @property
    def offset(self) -> int:
        return self.args[1]

    def __str__(self) -> str:
        return "call-back-table@" + str(self.address)


@apiregistry.register_tag("u", CallTarget)
class UnknownTarget(CallTarget):
    """Unknown call target; no information about function being called."""

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            ixval: IndexedTableValue) -> None:
        CallTarget.__init__(self, d, ixval)

    @property
    def is_unknown(self) -> bool:
        return True
