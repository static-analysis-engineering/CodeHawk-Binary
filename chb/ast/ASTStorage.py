# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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
"""Representation for variable storage."""


from typing import Dict, List, Optional, Union


class ASTStorage:

    def __init__(self, kind: str, size: Optional[int] = None) -> None:
        self._kind = kind
        self._size = size

    def has_size(self) -> bool:
        return self.size is not None

    @property
    def is_register(self) -> bool:
        return False

    @property
    def is_double_register(self) -> bool:
        return False

    @property
    def is_flag(self) -> bool:
        return False

    @property
    def is_stack(self) -> bool:
        return False

    @property
    def is_global(self) -> bool:
        return False

    @property
    def is_base_location(self) -> bool:
        return False

    @property
    def kind(self) -> str:
        return self._kind

    @property
    def size(self) -> Optional[int]:
        return self._size

    def serialize(self) -> Dict[str, Union[str, int]]:
        result: Dict[str, Union[str, int]] = {}
        result["kind"] = self.kind
        if self.size is not None:
            result["size"] = self.size
        return result


class ASTRegisterStorage(ASTStorage):

    def __init__(self, name: str, size: Optional[int]) -> None:
        ASTStorage.__init__(self, "register", size)
        self._name = name

    @property
    def is_register(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return self._name

    def serialize(self) -> Dict[str, Union[str, int]]:
        result = ASTStorage.serialize(self)
        result["name"] = self.name
        return result

    def __str__(self) -> str:
        return self._name


class ASTDoubleRegisterStorage(ASTStorage):

    def __init__(self, name1: str, name2: str, size: Optional[int]) -> None:
        ASTStorage.__init__(self,"doubleregister", size)
        self._name1 = name1
        self._name2 = name2

    @property
    def is_double_register(self) -> bool:
        return True

    @property
    def name1(self) -> str:
        return self._name1

    @property
    def name2(self) -> str:
        return self._name2

    @property
    def name(self) -> str:
        return self.name1 + "_" + self.name2

    def serialize(self)-> Dict[str, Union[str, int]]:
        result = ASTStorage.serialize(self)
        result["name"] = self.name
        return result

    def __str__(self) -> str:
        return self.name


class ASTFlagStorage(ASTStorage):

    def __init__(self, name: str) -> None:
        ASTStorage.__init__(self, "flag")
        self._name = name

    @property
    def is_flag(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return self._name

    def serialize(self) -> Dict[str, Union[str, int]]:
        result = ASTStorage.serialize(self)
        result["name"] = self.name
        return result

    def __str__(self) -> str:
        return self.name


class ASTStackStorage(ASTStorage):

    def __init__(self, offset: int, size: Optional[int]) -> None:
        ASTStorage.__init__(self, "stack", size)
        self._offset = offset

    @property
    def is_stack(self) -> bool:
        return True

    @property
    def offset(self) -> int:
        return self._offset

    def serialize(self) -> Dict[str, Union[str, int]]:
        result = ASTStorage.serialize(self)
        result["offset"] = self.offset
        return result

    def __str__(self) -> str:
        if self.offset == 0:
            return "stack:0"
        elif self.offset > 0:
            return "parentstack:" + str(self.offset)
        else:
            return "localstack:" + str(-self.offset)


class ASTBaseStorage(ASTStorage):

    def __init__(self, base: str, offset: int, size: Optional[int]) -> None:
        ASTStorage.__init__(self, "heap", size)
        self._base = base
        self._offset = offset

    @property
    def is_base_location(self) -> bool:
        return True

    @property
    def base(self) -> str:
        return self._base

    @property
    def offset(self) -> int:
        return self._offset

    def serialize(self) -> Dict[str, Union[str, int]]:
        result = ASTStorage.serialize(self)
        result["base"] = self.base
        result["offset"] = self.offset
        return result

    def __str__(self) -> str:
        return self.base + ":" + str(self.offset)


class ASTGlobalStorage(ASTStorage):

    def __init__(self, address: str, size: Optional[int]) -> None:
        ASTStorage.__init__(self, "global", size)
        self._address = address

    @property
    def is_global(self) -> bool:
        return True

    @property
    def address(self) -> str:
        return self._address

    def serialize(self) -> Dict[str, Union[str, int]]:
        result = ASTStorage.serialize(self)
        result["address"] = self.address
        return result

    def __str__(self) -> str:
        return "global:" + self.address


class ASTStorageConstructor:

    def __init__(
            self,
            registersizes: Dict[str, int],
            defaultsize: Optional[int] = None,
            flagnames: List[str] = []) -> None:
        self._registersizes = registersizes
        self._defaultsize = defaultsize
        self._flagnames = flagnames

    @property
    def register_sizes(self) -> Dict[str, int]:
        return self._registersizes

    @property
    def flagnames(self) -> List[str]:
        return self._flagnames

    @property
    def default_size(self) -> Optional[int]:
        return self._defaultsize

    def has_register(self, name: str) -> bool:
        return name in self.register_sizes

    def has_flag(self, name: str) -> bool:
        return name in self.flagnames

    def register_size(self, name: str) -> int:
        if self.has_register(name):
            return self.register_sizes[name]
        else:
            raise Exception("Register with name " + name + " not found")

    def get_default_size(self, size: Optional[int]) -> Optional[int]:
        if size is None:
            return self.default_size
        else:
            return size

    def mk_register_storage(self, name: str) -> ASTRegisterStorage:
        if self.has_register(name):
            return ASTRegisterStorage(name, self.register_size(name))
        else:
            raise Exception("No register with name " + str(name))

    def mk_double_register_storage(
            self, name1: str, name2:str) -> ASTDoubleRegisterStorage:
        if self.has_register(name1) and self.has_register(name2):
            return ASTDoubleRegisterStorage(
                name1, name2, self.register_size(name1) + self.register_size(name2))
        else:
            raise Exception("No register with name " + name1 + " or " + name2)

    def mk_flag_storage(self, name: str) -> ASTFlagStorage:
        if self.has_flag(name):
            return ASTFlagStorage(name)
        else:
            raise Exception("No flag with name " + name)

    def mk_stack_storage(
            self, offset: int, size: Optional[int] = None) -> ASTStackStorage:
        size = self.get_default_size(size)
        return ASTStackStorage(offset, size)

    def mk_base_storage(
            self, base: str, offset: int, size: Optional[int]) -> ASTBaseStorage:
        size = self.get_default_size(size)
        return ASTBaseStorage(base, offset, size)

    def mk_global_storage(
            self, address: str, size: Optional[int]) -> ASTGlobalStorage:
        size = self.get_default_size(size)
        return ASTGlobalStorage(address, size)
