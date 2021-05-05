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
"""Function stub.

Based on function_stub_t in bchlib/bCHLibTypes:
                                                    tags[0]   tags    args
type function_stub_t =
  | SOFunction of string (* ELF *)                   "so"      1       1
  | DllFunction of string * string (* PE *)         "dll"      1       2
  | JniFunction of int                              "jni"      1       1
      (* Java Native Methods, call on
        ( *env) where env is the
        first argument on the calling function,
        with the jni identification number *)
  | LinuxSyscallFunction of int                      "sc"      1       1
        (* numbers ranging from 4000 to 4999 *)
  | PckFunction of string * string list * string    "pck"      1   2 + len(packages)
        (* PE, with package names *)

"""
from typing import List, TYPE_CHECKING

import chb.api.InterfaceDictionaryRecord as D
import chb.models.FunctionSummary as F
import chb.util.fileutil as UF

if TYPE_CHECKING:
    import chb.api.InterfaceDictionary


class FunctionStub(D.InterfaceDictionaryRecord):

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        D.InterfaceDictionaryRecord.__init__(self, d, index, tags, args)

    def is_dll_stub(self) -> bool:
        return False

    def is_so_stub(self) -> bool:
        return False

    def is_syscall_stub(self) -> bool:
        return False

    @property
    def dll(self) -> str:
        raise UF.CHBError("Dll not supported for " + str(self))

    @property
    def name(self) -> str:
        raise UF.CHBError("Name not supported for " + str(self))

    def __str__(self) -> str:
        return 'function-stub:' + self.tags[0]


@D.apiregistry.register_tag("so", FunctionStub)
class SOFunction(FunctionStub):
    """Shared object library function (ELF) stub.

    args[0]: index of name in bd string-table
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        FunctionStub.__init__(self, d, index, tags, args)

    @property
    def name(self) -> str:
        return self.bd.get_string(self.args[0])

    def has_summary(self) -> bool:
        return self.models.has_so_function_summary(self.name)

    def get_summary(self) -> F.FunctionSummary:
        if self.has_summary():
            return self.models.get_so_function_summary(self.name)
        else:
            raise UF.CHBError("No so function summary found for " + self.name)

    def is_so_stub(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.name


@D.apiregistry.register_tag("sc", FunctionStub)
class SyscallFunction(FunctionStub):
    """System call stub (ELF).

    args[0]: index of system call (architecture dependent)
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        FunctionStub.__init__(self, d, index, tags, args)

    @property
    def index(self) -> int:
        return self.args[0]

    def is_syscall_stub(self) -> bool:
        return True

    def __str__(self) -> str:
        return 'syscall-' + str(self.index)


@D.apiregistry.register_tag("dll", FunctionStub)
class DllFunction(FunctionStub):
    """Dll function stub (PE).

    args[0]: index of dll name in bd string table
    args[1]: index of function name in bd string table
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        FunctionStub.__init__(self, d, index, tags, args)

    @property
    def dll(self) -> str:
        return self.bd.get_string(self.args[0])

    @property
    def name(self) -> str:
        return self.bd.get_string(self.args[1])

    def is_dll_stub(self) -> bool:
        return True

    def has_summary(self) -> bool:
        return self.models.has_dll_function_summary(self.dll, self.name)

    def get_summary(self) -> F.FunctionSummary:
        if self.has_summary():
            return self.models.get_dll_function_summary(self.dll, self.name)
        else:
            raise UF.CHBError("No dll summary found for "
                              + self.dll
                              + ":"
                              + self.name)

    def __str__(self) -> str:
        return self.dll + ":" + self.name


@D.apiregistry.register_tag("jni", FunctionStub)
class JniFunction(FunctionStub):
    """Java native method function stub (PE)

    args[0]: index of jni method
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        FunctionStub.__init__(self, d, index, tags, args)

    @property
    def jni_index(self) -> int:
        return self.args[0]

    def __str__(self) -> str:
        return 'Jni:' + str(self.index)


@D.apiregistry.register_tag("pck", FunctionStub)
class PckFunction(FunctionStub):
    """Library function stub from a C++ package.

    args[0]: index of library name in bd
    args[1]: index of function name in bd
    args[2..]: indices of package name components
    """

    def __init__(
            self,
            d: "chb.api.InterfaceDictionary.InterfaceDictionary",
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        FunctionStub.__init__(self, d, index, tags, args)

    @property
    def lib(self) -> str:
        return self.bd.get_string(self.args[0])

    @property
    def name(self) -> str:
        return self.bd.get_string(self.args[1])

    @property
    def packages(self) -> List[str]:
        return [self.bd.get_string(i) for i in self.args[2:]]

    def __str__(self) -> str:
        return (self.lib + ":" + "::".join(self.packages) + "::" + self.name)
