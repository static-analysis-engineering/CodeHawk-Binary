# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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

import string

from abc import ABC, abstractmethod

from typing import Any, BinaryIO, cast, Dict, IO, List, Mapping, Optional, Tuple

import chb.simulation.SimUtil as SU
import chb.simulation.SimValue as SV

import chb.util.fileutil as UF


# convenience functions


def mk_global_address(address: int, modulename: str) -> "SimGlobalAddress":
    offset = cast(SV.SimDoubleWordValue, SV.mk_simvalue(address, size=4))
    return SimGlobalAddress(modulename, offset)


def mk_return_address(
        address: int, modulename: str, function: str) -> "SimReturnAddress":
    offset = cast(SV.SimDoubleWordValue, SV.mk_simvalue(address, size=4))
    return SimReturnAddress(modulename, function, offset)


def pc_to_return_address(pc: "SimGlobalAddress", function: str) -> "SimReturnAddress":
    return SimReturnAddress(pc.modulename, function, pc.offset)


def mk_undefined_global_address(modulename: str) -> "SimGlobalAddress":
    return SimGlobalAddress(modulename, SV.simUndefinedDW)


def mk_stack_address(stackoffset: int) -> "SimStackAddress":
    offset = cast(SV.SimDoubleWordValue, SV.mk_simvalue(stackoffset, size=4))
    return SimStackAddress(offset)


def mk_mapped_address(
        base: str,
        offset: int,
        buffersize: int) -> "SimMappedAddress":
    """Makes an address within a memory-mapped region."""

    return SimMappedAddress(
        base,
        cast(SV.SimDoubleWordValue, SV.mk_simvalue(offset, size=4)),
        buffersize)


def mk_base_address(
        base: str,
        offset: int = 0,
        buffersize: Optional[int] = None,
        tgttype: Optional[str] = None) -> "SimBaseAddress":
    """Makes a base address with offset (int) and buffer size (simvalue)."""

    return SimBaseAddress(
        base,
        cast(SV.SimDoubleWordValue, SV.mk_simvalue(offset, size=4)),
        buffersize=buffersize,
        tgttype=tgttype)


def mk_string_address(s: str) -> "SimStringAddress":
    return SimStringAddress(s)


def mk_symbol(
        name: str,
        type: Optional[str] = None,
        minval: Optional[int] = None,
        maxval: Optional[int] = None) -> "SimSymbol":
    return SimSymbol(name, type=type, minval=minval, maxval=maxval)


def mk_libc_table_address(name: str) -> "SimLibcTableAddress":
    return SimLibcTableAddress(name)


def mk_libc_table_value(name: str, offset: int = 0) -> "SimLibcTableValue":
    return SimLibcTableValue(name, offset)


def mk_libc_table_value_deref(
        name: str, offset1: int = 0, offset2: int = 0) -> "SimLibcTableValueDeref":
    return SimLibcTableValueDeref(name, offset1, offset2)


def mk_filepointer(
        filename: str,
        simfilename: str,
        filepointer: Any,
        defined: bool = True) -> "SimSymbolicFilePointer":
    return SimSymbolicFilePointer(filename, simfilename, filepointer, defined=defined)


def mk_filedescriptor(
        filename: str,
        filedescriptor: Any) -> "SimSymbolicFileDescriptor":
    return SimSymbolicFileDescriptor(filename, filedescriptor)


def mk_symboltablehandle(name: str) -> "SimSymbolTableHandle":
    return SimSymbolTableHandle(name)


def mk_dynamic_link_symbol(
        handle: "SimSymbolTableHandle",
        name: str,
        addr: "SimGlobalAddress") -> "SimDynamicLinkSymbol":
    return SimDynamicLinkSymbol(handle, name, addr)


class SimSymbolicValue(SV.SimValue):
    """Symbolic representation of a value in a register or memory location.

    A SimSymbolicValue does not have a value; it can be an address (e.g.,
    a stackaddress, for which we would not have a concrete value,
    only an offset from some reference point), or a pointer to a constant
    string (e.g., a string returned by getenv or basename), or a symbolic
    value identified by a (meaningful) name (e.g., ra_in, signifying the
    value of the return register passed in at the start of the function).

    At this time SimSymbolicValues can be moved around, but we do not (yet)
    support manipulation of SimSymbolicValues to create symbolic expressions.
    """

    def __init__(self, size: int = 4, defined: bool = True):
        SV.SimValue.__init__(self, defined=defined)
        self._size = size
        self.expressions: List[Tuple[str, SV.SimValue]] = []

    @property
    def size(self) -> int:
        return self._size

    @property
    def width(self) -> int:
        return 8 * self.size

    @property
    def is_symbolic(self) -> bool:
        return True

    @property
    def is_address(self) -> bool:
        return False

    @property
    def is_global_address(self) -> bool:
        return False

    @property
    def is_mapped_address(self) -> bool:
        return False

    @property
    def is_stack_address(self) -> bool:
        return False

    @property
    def is_base_address(self) -> bool:
        return False

    @property
    def is_string_address(self) -> bool:
        return False

    @property
    def is_symbolic_return_address(self) -> bool:
        return False

    @property
    def is_libc_table_address(self) -> bool:
        return False

    @property
    def is_libc_table_value(self) -> bool:
        return False

    @property
    def is_libc_table_value_deref(self) -> bool:
        return False

    @property
    def is_symbol(self) -> bool:
        return False

    @property
    def is_environment_string(self) -> bool:
        return False

    @property
    def is_environment_string_entry(self) -> bool:
        return False

    @property
    def is_tainted_data(self) -> bool:
        return False

    @property
    def is_file_pointer(self) -> bool:
        return False

    @property
    def is_file_descriptor(self) -> bool:
        return False

    @property
    def is_dynamic_link_symbol(self) -> bool:
        return False

    def __str__(self) -> str:
        return "symbolic value"


class SimAddress(SimSymbolicValue, ABC):

    def __init__(
            self, base: str, offset: SV.SimDoubleWordValue, defined: bool = True):
        SimSymbolicValue.__init__(self, size=4, defined=defined)
        self._base = base      # 'global', 'stack', baseaddress
        self._offset = offset

    @property
    def base(self) -> str:
        return self._base

    @property
    def offset(self) -> SV.SimDoubleWordValue:
        return self._offset

    @property
    def offsetvalue(self) -> int:
        if self.offset.is_defined:
            return self.offset.to_signed_int()
        else:
            raise UF.CHBError("Address offset is not defined: "
                              + str(self))

    @property
    def alignment(self) -> int:
        return self.offsetvalue % 4

    @abstractmethod
    def add_offset(self, v: int) -> "SimAddress":
        ...

    @abstractmethod
    def align(self, v: int) -> "SimAddress":
        ...

    @abstractmethod
    def is_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        ...

    def is_not_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        isequal = self.is_equal(other)
        if isequal.is_defined:
            if isequal.is_true:
                return SV.simfalse
            else:
                return SV.simtrue
        else:
            return SV.simUndefinedBool

    @property
    def is_address(self) -> bool:
        return True

    @property
    def is_null_pointer(self) -> bool:
        return False

    def is_aligned(self, size: int = 4) -> bool:
        return (self.offset.value % size) == 0

    @property
    def is_defined(self) -> bool:
        return self.offset.is_defined

    @property
    def is_global_address(self) -> bool:
        return False

    @property
    def is_return_address(self) -> bool:
        return False

    @property
    def is_stack_address(self) -> bool:
        return False

    @property
    def is_base_address(self) -> bool:
        return False

    def to_hex(self) -> str:
        return hex(self.offset.value)

    def __str__(self) -> str:
        return self.base + ':' + str(self.to_hex())


class SimMappedAddress(SimAddress):
    """Address in a memory-mapped region, offset is absolute, like a global address."""

    def __init__(self, base: str, offset: SV.SimDoubleWordValue, buffersize: int) -> None:
        SimAddress.__init__(self, "mapped:" + base + ":", offset)
        self._buffersize = buffersize

    @property
    def is_mapped_address(self) -> bool:
        return True

    @property
    def buffersize(self) -> int:
        return self._buffersize

    def add_offset(self, v: int) -> "SimMappedAddress":
        newoffset = self.offset.add_int(v)
        return SimMappedAddress(self.base, newoffset, self.buffersize)

    def align(self, v: int) -> "SimMappedAddress":
        newoffset = self.offset.bitwise_and(SV.mk_simvalue(v))
        return SimMappedAddress(self.base, newoffset, self.buffersize)

    def is_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        if self.is_defined and other.is_defined:
            if other.is_literal:
                other = cast(SV.SimLiteralValue, other)
                if other.value == 0:
                    return SV.simfalse
                elif other.value == self.offsetvalue:
                    return SV.simtrue
                else:
                    return SV.simfalse
            elif other.is_symbolic:
                other = cast(SimSymbolicValue, other)
                if other.is_global_address:
                    other = cast("SimGlobalAddress", other)
                    if other.offsetvalue == self.offsetvalue:
                        return SV.simtrue
                    else:
                        return SV.simfalse
                else:
                    return SV.simfalse
            else:
                return SV.simUndefinedBool
        else:
            return SV.simUndefinedBool
        return SV.simUndefinedBool

    def __str__(self) -> str:
        return self.base + self.to_hex()


class SimGlobalAddress(SimAddress):

    def __init__(self, modulename: str, offset: SV.SimDoubleWordValue) -> None:
        SimAddress.__init__(self, "global:" + modulename, offset)
        self._modulename = modulename

    def jsonval(self) -> Dict[str, Any]:
        """Serialize object to json."""

        result: Dict[str, Any] = {}
        result["i"] = "sga"
        result["d"] = {}
        result["d"]["m"] = self.modulename
        result["d"]["o"] = self.offset.jsonval()
        return result

    @property
    def is_literal(self) -> bool:
        """Special case where we can't distinguish between global address and literal."""

        return True

    @property
    def literal_value(self) -> int:
        """Returns the offset value of the global address as a literal value."""

        return self.offsetvalue

    @property
    def modulename(self) -> str:
        """Return name of loaded module where address resides."""

        return self._modulename

    @property
    def is_global_address(self) -> bool:
        return True

    def add_offset(self, v: int) -> "SimGlobalAddress":
        newoffset = self.offset.add_int(v)
        return SimGlobalAddress(self.modulename, newoffset)

    def align(self, v: int) -> "SimGlobalAddress":
        newoffset = self.offset.bitwise_and(SV.mk_simvalue(v))
        return SimGlobalAddress(self.modulename, newoffset)

    def is_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        """Return simtrue if the other address is the same address.

        Three cases:
        - Other is a scalar value: this is considered equal if
            the offsetvalue of this address has the same value;
            this is considered not equal if the other value is 0
            (a valid global address is assumed not be 0)
        - Other is a global address: this is considered equal
            if the offsetvalues are the same
        - Self, or other have undefined values: in this case the
            the return value is an undefined boolvalue.
        """

        if self.is_defined and other.is_defined:
            if other.is_literal:
                other = cast(SV.SimLiteralValue, other)
                if other.value == 0:
                    return SV.simfalse
                elif other.value == self.offsetvalue:
                    return SV.simtrue
                else:
                    return SV.simfalse
            elif other.is_symbolic:
                other = cast(SimSymbolicValue, other)
                if other.is_global_address:
                    other = cast("SimGlobalAddress", other)
                    if other.offsetvalue == self.offsetvalue:
                        return SV.simtrue
                    else:
                        return SV.simfalse
                else:
                    return SV.simfalse
            else:
                return SV.simUndefinedBool
        else:
            return SV.simUndefinedBool

    def add(self, simval: SV.SimLiteralValue) -> "SimGlobalAddress":
        return self.add_offset(simval.to_signed_int())

    def sub(self, simval: SV.SimLiteralValue) -> "SimGlobalAddress":
        return self.add_offset(-simval.to_signed_int())

    def __str__(self) -> str:
        if self.is_defined:
            return str(self.modulename + ":" + self.to_hex())
        else:
            return self.modulename + ":undefined"


class SimNullPointer(SimGlobalAddress):

    def __init__(self) -> None:
        SimGlobalAddress.__init__(self, "null", SV.simZero)

    @property
    def is_null_pointer(self) -> bool:
        return True

    def add_offset(self, v: int) -> "SimGlobalAddress":
        raise UF.CHBError("Attempt to add offset to nullpointer: " + str(v))

    def align(self, v: int) -> "SimGlobalAddress":
        return self

    def is_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        if other.is_defined:
            if other.is_literal:
                if other.literal_value == 0:
                    return SV.simtrue
                else:
                    return SV.simfalse
            else:
                return SV.simfalse
        else:
            return SV.simUndefinedBool

    def __str__(self) -> str:
        return "NULL"


nullpointer = SimNullPointer()


class SimReturnAddress(SimGlobalAddress):

    def __init__(
            self,
            modulename: str,
            functionaddr: str,
            offset: SV.SimDoubleWordValue) -> None:
        SimGlobalAddress.__init__(self, modulename, offset)
        self._functionaddr = functionaddr

    def jsonval(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        result["i"] = "sra"
        result["d"] = {}
        result["d"]["f"] = self.functionaddr
        result["d"]["m"] = self.modulename
        result["d"]["o"] = self.offset.jsonval()
        return result

    @property
    def functionaddr(self) -> str:
        return self._functionaddr

    @property
    def is_function_return_address(self) -> bool:
        return True

    def __str__(self) -> str:
        return (
            "RA:"
            + str(self.modulename)
            + ":"
            + self.functionaddr
            + ":" + self.to_hex())


class SimStackAddress(SimAddress):

    def __init__(self, offset: SV.SimDoubleWordValue) -> None:
        SimAddress.__init__(self, "stack", offset)

    @property
    def is_stack_address(self) -> bool:
        return True

    def add_offset(self, v: int) -> "SimStackAddress":
        newoffset = self.offset.add_int(v)
        return SimStackAddress(newoffset)

    def align(self, v: int) -> "SimStackAddress":
        newoffset = self.offset.bitwise_and(SV.mk_simvalue(v))
        return SimStackAddress(newoffset)

    def is_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        """Return simtrue if the other address is the same stack address.

        Returns false if the other value is a scalar with value 0. Returns
        undefined if the other value is neither a stack address nor 0.
        """

        if self.is_defined and other.is_defined:
            if other.is_literal:
                other = cast(SV.SimLiteralValue, other)
                if other.value == 0:
                    return SV.simfalse
                else:
                    return SV.simUndefinedBool
            elif other.is_symbolic:
                other = cast(SimSymbolicValue, other)
                if other.is_stack_address:
                    other = cast("SimStackAddress", other)
                    if other.offsetvalue == self.offsetvalue:
                        return SV.simtrue
                    else:
                        return SV.simfalse
                else:
                    return SV.simUndefinedBool
            else:
                return SV.simUndefinedBool
        else:
            return SV.simUndefinedBool

    def add(self, simval: SV.SimLiteralValue) -> "SimStackAddress":
        return self.add_offset(simval.to_signed_int())

    def sub(self, simval: SV.SimLiteralValue) -> "SimStackAddress":
        return self.add_offset(-simval.to_signed_int())

    def subu(self, simval: SV.SimValue) -> SV.SimValue:
        """Unsigned subtraction.

        This may be either subtraction of another stackaddress, resulting
        in a scalar, or subtraction of a scalar, resulting in another
        stack address.
        """

        if simval.is_literal and simval.is_defined:
            simval = cast(SV.SimLiteralValue, simval)
            return self.add_offset(-simval.value)
        elif simval.is_symbolic:
            simval = cast(SimSymbolicValue, simval)
            if simval.is_stack_address:
                simval = cast("SimStackAddress", simval)
                return SV.mk_simvalue(
                    self.offsetvalue - simval.offsetvalue,
                    size=4)
            else:
                raise UF.CHBError("Illegal subtraction from stack address with: "
                                  + str(simval))
        else:
            return SV.simUndefinedDW

    def add_unsigned(self, simval: SV.SimLiteralValue) -> "SimStackAddress":
        return self.add_offset(simval.value)

    def bitwise_and(self, simval: SV.SimValue) -> "SimStackAddress":
        if simval.is_literal and simval.is_defined:
            simval = cast(SV.SimLiteralValue, simval)
            newoffset = self.offset.bitwise_and(simval)
            return SimStackAddress(newoffset)
        else:
            return SimStackAddress(SV.simUndefinedDW)

    def __str__(self) -> str:
        return str("stack:" + str(self.offset.to_signed_int()))


class SimBaseAddress(SimAddress):
    """Address with a symbolic, possibly unknown, base.

    Examples include address returned from malloc, or other allocation functions,
    or an unknown base pointer returned from another function, or passed in as an
    argument.
    """

    def __init__(
            self,
            base: str,
            offset: SV.SimDoubleWordValue,
            buffersize: Optional[int] = None,
            tgttype: Optional[str] = None) -> None:
        SimAddress.__init__(self, base, offset)
        self._buffersize = buffersize
        self._tgttype = tgttype

    @property
    def buffersize(self) -> Optional[int]:
        return self._buffersize

    def has_buffer_size(self) -> bool:
        return self.buffersize is not None

    @property
    def tgttype(self) -> Optional[str]:
        return self._tgttype

    def has_target_type(self) -> bool:
        return self.tgttype is not None

    @property
    def is_base_address(self) -> bool:
        return True

    def is_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        if other.is_literal and other.is_defined:
            other = cast(SV.SimLiteralValue, other)
            if other.is_zero:
                return SV.simfalse
            else:
                return SV.simUndefinedBool
        else:
            return SV.simUndefinedBool

    def add_offset(self, v: int) -> "SimBaseAddress":
        newoffset = self.offset.add_int(v)
        return SimBaseAddress(
            self.base, newoffset, buffersize=self.buffersize, tgttype=self.tgttype)

    def align(self, v: int) -> "SimBaseAddress":
        newoffset = self.offset.bitwise_and(SV.mk_simvalue(v))
        return SimBaseAddress(
            self.base, newoffset, buffersize=self.buffersize, tgttype=self.tgttype)

    def add(self, simval: SV.SimLiteralValue) -> "SimBaseAddress":
        return self.add_offset(simval.to_signed_int())

    def sub(self, simval: SV.SimLiteralValue) -> "SimBaseAddress":
        return self.add_offset(-simval.to_signed_int())

    def subu(self, simval: SV.SimValue) -> SV.SimValue:
        if simval.is_literal and simval.is_defined:
            simval = cast(SV.SimLiteralValue, simval)
            return self.add_offset(-simval.value)
        elif simval.is_symbolic:
            simval = cast(SimSymbolicValue, simval)
            if simval.is_base_address:
                simval = cast("SimBaseAddress", simval)
                if simval.base == self.base:
                    return SV.mk_simvalue(self.offsetvalue - simval.offsetvalue)
                else:
                    return SV.simUndefinedDW
            else:
                return SV.simUndefinedDW
        else:
            return SV.simUndefinedDW

    def add_unsigned(self, simval: SV.SimLiteralValue) -> "SimBaseAddress":
        return self.add_offset(simval.value)

    def __str__(self) -> str:
        return self.base + ':' + str(self.offset.to_signed_int())


class SimSymbolicReturnAddress(SimSymbolicValue):
    """Address recorded for return after a function call."""

    def __init__(self) -> None:
        SimSymbolicValue.__init__(self)

    @property
    def is_symbolic_return_address(self) -> bool:
        return True


class SimStringAddress(SimSymbolicValue):
    """Address of a constant string."""

    def __init__(self, stringval: str) -> None:
        SimSymbolicValue.__init__(self)
        self._stringval = stringval

    @property
    def stringval(self) -> str:
        """Return the string pointed to by this address."""

        return self._stringval

    @property
    def is_string_address(self) -> bool:
        return True

    def add(self, v: SV.SimValue) -> "SimStringAddress":
        if v.is_literal and v.is_defined:
            v = cast(SV.SimLiteralValue, v)
            if v.value == 0:
                return self
            elif v.value > 0:
                if len(self.stringval) > v.value:
                    return mk_string_address(self.stringval[v.value:])
                elif len(self.stringval) == v.value:
                    return mk_string_address("")
                else:
                    raise UF.CHBError('Cannot add ' + str(v.value)
                                      + ' to string of length: '
                                      + str(len(self.stringval)))
            else:
                raise UF.CHBError('Unable to add negative number to string address: '
                                  + str(v.value))
        else:
            raise UF.CHBError('String address: value to be added is undefined')

    def __str__(self) -> str:
        if len(self.stringval) < 100:
            return "string:" + self.stringval
        else:
            return (
                "string[length:"
                + str(len(self.stringval))
                + "]:"
                + self.stringval[:100])


class SimLibcTableAddress(SimSymbolicValue):
    """Represents the address of a table in libc that implements some function.

    Typically used for functions like isalpha, etc.
    """

    def __init__(self, name: str) -> None:
        SimSymbolicValue.__init__(self)
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_libc_table_address(self) -> bool:
        return True

    def __str__(self) -> str:
        return "libc-table-address:" + self.name


class SimLibcTableValue(SimSymbolicValue):
    """Represents a value within a table in libc that implements some function."""

    def __init__(self, name: str, offset: int = 0) -> None:
        SimSymbolicValue.__init__(self)
        self._name = name
        self._offset = offset

    @property
    def name(self) -> str:
        return self._name

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def is_libc_table_value(self) -> bool:
        return True

    def add(self, other: SV.SimLiteralValue) -> "SimLibcTableValue":
        if other.is_defined:
            return mk_libc_table_value(self.name, self.offset + other.value)
        else:
            raise UF.CHBError('Argument to libc-table-value.add not recognized: ' +
                              str(other))

    def b_result(self) -> SV.SimLiteralValue:
        if self.name == "ctype_b":
            result = 0
            print("ctype_b: " + str(self.offset) + ', ' + str(chr(self.offset // 2)))
            c = chr(self.offset // 2)
            if c.isspace():
                result += 32
            return SV.mk_simvalue(result)
        else:
            return SV.simZero

    def __str__(self) -> str:
        poffset = '' if self.offset == 0 else '[' + str(self.offset) + ']'
        return "libc-table-value:" + self.name + poffset


class SimLibcTableValueDeref(SimSymbolicValue):

    def __init__(
            self,
            name: str,
            offset1: int = 0,
            offset2: int = 0) -> None:
        SimSymbolicValue.__init__(self)
        self._name = name
        self._offset1 = offset1
        self._offset2 = offset2

    @property
    def name(self) -> str:
        return self._name

    @property
    def offset1(self) -> int:
        return self._offset1

    @property
    def offset2(self) -> int:
        return self._offset2

    @property
    def is_libc_table_value_deref(self) -> bool:
        return True

    def toupper_result(self) -> SV.SimLiteralValue:
        if self.name == "ctype_toupper":
            if self.offset1 >= 97 and self.offset2 <= 122:
                return SV.mk_simvalue(self.offset1 // 2)
            else:
                return SV.mk_simvalue(self.offset1)
        else:
            return SV.simUndefinedDW

    def b_result(self) -> SV.SimLiteralValue:
        if self.name == "ctype_b":
            result = 0
            print("ctype_b deref table value: "
                  + str(self.offset1)
                  + ", "
                  + str(chr(self.offset1 // 2)))
            c = str(chr(self.offset1 // 2))
            if c.isupper():
                result += 1
            if c.islower():
                result += 2
            if c.isalpha():
                result += 4
            if c.isnumeric():
                result += 8
            if c.isspace() or c == '\r' or c == '\n':
                result += 32
            if c.isprintable():
                result += 64
            if c.isspace():
                result += 256
            if not c.isprintable():
                result += 512
            if c in string.punctuation:
                result += 1024
            if c.isalnum():
                result += 2048
            return SV.mk_simvalue(result)
        else:
            return SV.simZero

    def __str__(self) -> str:
        return ('libc-table-value-deref:' + self.name
                + '[' + str(self.offset1) + ']'
                + '[' + str(self.offset2) + ']')


class SimSymbol(SimSymbolicValue):
    """Represents a symbolic scalar value.

    Used in cases where a value is received that may be bounded in
    some ways, but for which a concrete value is not available, e.g.,
    because it originated from user input.
    """

    def __init__(
            self,
            name: str,
            type: Optional[str] = None,
            minval: Optional[int] = None,
            maxval: Optional[int] = None,
            defined: bool = True) -> None:
        SimSymbolicValue.__init__(self, defined=defined)
        self._name = name
        self._type = type
        self._minval = minval
        self._maxval = maxval

    @property
    def name(self) -> str:
        return self._name

    @property
    def valuetype(self) -> Optional[str]:
        return self._type

    @property
    def value(self) -> Optional[int]:
        if (
                self.minval is not None
                and self.maxval is not None
                and self.minval == self.maxval):
            return self.minval
        else:
            return None

    @property
    def minval(self) -> Optional[int]:
        return self._minval

    @property
    def maxval(self) -> Optional[int]:
        return self._maxval

    @property
    def lowerbound(self) -> int:
        if self.minval is not None:
            return self.minval
        else:
            raise UF.CHBError("Symbolic value has no lowerbound: " + str(self))

    @property
    def upperbound(self) -> int:
        if self.maxval is not None:
            return self.maxval
        else:
            raise UF.CHBError("Symbolic value has no upperbound: " + str(self))

    @property
    def is_symbol(self) -> bool:
        return True

    def is_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        return SV.simfalse    # not equal to anything

    def is_not_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        return SV.simfalse

    @property
    def is_non_negative(self) -> SV.SimBoolValue:
        """Return true if it is bounded from below by zero."""

        if self.has_minval() and self.lowerbound >= 0:
            return SV.simtrue
        elif self.has_maxval() and self.upperbound < 0:
            return SV.simfalse
        else:
            return SV.simUndefinedBool

    @property
    def is_positive(self) -> SV.SimBoolValue:
        """Return true if it is bounded from below by one."""

        if self.has_minval() and self.lowerbound >= 1:
            return SV.simtrue
        elif self.has_maxval() and self.upperbound <= 0:
            return SV.simfalse
        else:
            return SV.simUndefinedBool

    @property
    def is_non_positive(self) -> SV.SimBoolValue:
        """Return true if it is bounded from above by zero."""

        if self.has_maxval() and self.upperbound <= 0:
            return SV.simtrue
        elif self.has_minval() and self.lowerbound > 0:
            return SV.simfalse
        else:
            return SV.simUndefinedBool

    @property
    def is_negative(self) -> SV.SimBoolValue:
        """Return true if it is bounded from above by zero."""

        if self.has_minval() and self.lowerbound >= 0:
            return SV.simfalse
        elif self.has_maxval() and self.upperbound < 0:
            return SV.simtrue
        else:
            return SV.simUndefinedBool

    def has_minval(self) -> bool:
        return self.minval is not None

    def has_maxval(self) -> bool:
        return self.maxval is not None

    def has_type(self) -> bool:
        return self.valuetype is not None

    def __str__(self) -> str:
        ptype = ""
        if self.valuetype is not None:
            ptype = '[type:' + self.valuetype + ']'
        if self.has_minval() and self.has_maxval():
            prange = ' [' + str(self.lowerbound) + '..' + str(self.upperbound) + ']'
        elif self.has_minval():
            prange = ' [' + str(self.lowerbound) + '... ]'
        elif self.has_maxval():
            prange = ' [ ... ' + str(self.upperbound) + ']'
        else:
            prange = ''
        return 'sym:' + self.name + ptype + prange


class SimSymbolicFilePointer(SimSymbol):
    """Represents a pointer to a FILE struct.

    This object keeps the actual filepointer returned by the python
    'open' function call, so it can actually read from the file
    provided.
    """

    def __init__(
            self, filename: str,
            simfilename: str,
            fp: Any, defined: bool = True):
        SimSymbol.__init__(
            self, filename + '_filepointer', type='ptr2FILE', defined=defined)
        self._filename = filename
        self._simfilename = simfilename
        self._fp = fp    # pointer returned by open
        if self._filename == "/stderr":
            self._minval = 2
            self._maxval = 2

    # Dictionary keys are the filenames as used in the binary
    openfiles: Dict[str, "SimSymbolicFilePointer"] = {}

    @classmethod
    def add_openfile(cls, name: str, fp: "SimSymbolicFilePointer") -> None:
        cls.openfiles[name] = fp

    @classmethod
    def has_openfile(cls, name) -> bool:
        return name in cls.openfiles

    @classmethod
    def openfile(cls, name) -> "SimSymbolicFilePointer":
        if cls.has_openfile(name):
            return cls.openfiles[name]
        else:
            raise UF.CHBError("No open file found for: " + name)

    @classmethod
    def closefile(cls, name) -> None:
        if cls.has_openfile(name):
            del cls.openfiles[name]

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def simfilename(self) -> str:
        return self._simfilename

    @property
    def fp(self) -> IO[Any]:
        return self._fp

    @property
    def is_file_pointer(self) -> bool:
        return True

    def is_not_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        if other.is_literal and other.is_defined:
            other = cast(SV.SimLiteralValue, other)
            if other.value == 0:
                return SV.simtrue
            else:
                return SV.simUndefinedBool
        else:
            return SV.simUndefinedBool

    def is_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        if other.is_literal and other.is_defined:
            other = cast(SV.SimLiteralValue, other)
            if other.value == 0:
                return SV.simfalse
            else:
                return SV.simUndefinedBool
        else:
            return SV.simUndefinedBool

    def __str__(self) -> str:
        return "fp_" + self.filename


class SimSymbolicFileDescriptor(SimSymbol):
    """Represents a file descriptor.

    It is assumed that this value is non-negative.
    """

    def __init__(self, filename: str, fd: IO[Any]) -> None:
        SimSymbol.__init__(self, filename + '_filedescriptor', type="int")
        self._filename = filename
        self._fd = fd

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def filedescriptor(self) -> IO[Any]:
        return self._fd

    @property
    def is_file_descriptor(self) -> bool:
        return True

    @property
    def is_non_negative(self) -> SV.SimBoolValue:
        return SV.simtrue

    @property
    def is_negative(self) -> SV.SimBoolValue:
        return SV.simfalse

    def is_not_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        if other.is_literal and other.is_defined:
            other = cast(SV.SimLiteralValue, other)
            if other.to_signed_int() == -1:
                return SV.simtrue
            else:
                return SV.simUndefinedBool
        else:
            return SV.simUndefinedBool

    def __str__(self) -> str:
        return 'fd_' + self.filename


class SimSymbolTableHandle(SimSymbol):

    def __init__(self, name: str) -> None:
        SimSymbol.__init__(self, "symboltablehandle:" + name)
        self._name = name
        self._table: Dict[str, SV.SimValue] = {}  # name -> symbol

    @property
    def table(self) -> Mapping[str, SV.SimValue]:
        return self._table

    def set_value(self, symname: str, symval: SV.SimValue) -> None:
        self._table[symname] = symval

    @property
    def is_symbol_table_handle(self) -> bool:
        return True

    @property
    def is_non_negative(self) -> SV.SimBoolValue:
        return SV.simtrue

    @property
    def is_negative(self) -> SV.SimBoolValue:
        return SV.simfalse

    def is_not_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        if other.is_literal and other.is_defined:
            other = cast(SV.SimLiteralValue, other)
            if other.to_signed_int() == 0:
                return SV.simtrue
            else:
                return SV.simUndefinedBool
        else:
            return SV.simUndefinedBool

    def __str__(self) -> str:
        return "symboltablehandle:" + self.name


class SimDynamicLinkSymbol(SimSymbol):

    def __init__(self, handle: SimSymbolTableHandle, name: str, addr: SimGlobalAddress):
        SimSymbol.__init__(self, "dlsym:" + name)
        self._handle = handle
        self._name = name
        self._addr = addr

    @property
    def name(self) -> str:
        return self._name

    @property
    def handle(self) -> SimSymbolTableHandle:
        return self._handle

    @property
    def address(self) -> SimGlobalAddress:
        return self._addr

    @property
    def is_dynamic_link_symbol(self) -> bool:
        return True

    def is_not_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        if other.is_literal and other.is_defined:
            other = cast(SV.SimLiteralValue, other)
            if other.to_signed_int() == 0:
                return SV.simtrue
            else:
                return SV.simUndefinedBool
        else:
            return SV.simUndefinedBool

    def __str__(self) -> str:
        return "dlsym:" + self.name


class SimEnvironmentString(SimSymbolicValue):
    """Represents the address of an environment string."""

    def __init__(self, offset: int) -> None:
        SimSymbolicValue.__init__(self)
        self._offset = offset

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def is_environment_string(self) -> bool:
        return True

    def __str__(self) -> str:
        return 'env:' + str(self.offset)


class SimEnvironmentStringEntry(SimSymbolicValue):
    """Element of the environment string (environment string dereferenced)."""

    def __init__(self, entryoffset: int):
        SimSymbolicValue.__init__(self)
        self._entryoffset = entryoffset

    @property
    def entryoffset(self) -> int:
        return self._entryoffset

    @property
    def is_environment_string_entry(self) -> bool:
        return True

    def __str__(self) -> str:
        return "env[" + str(self.entryoffset) + "]"


class SimTaintedData(SimSymbolicValue):
    """Super class for different kinds of tainted data."""

    def __init__(self, source: str) -> None:
        SimSymbolicValue.__init__(self)
        self._source = source

    @property
    def taintsource(self) -> str:
        return self._source

    @property
    def is_tainted_data(self) -> bool:
        return True

    @property
    def is_tainted_string(self) -> bool:
        return False

    @property
    def is_tainted_value(self) -> bool:
        return False

    def __str__(self) -> str:
        return "tainted[" + self.taintsource + ']'


class SimTaintedString(SimTaintedData):

    def __init__(
            self,
            source: str,
            length: Optional[int] = None,
            maxlen: Optional[int] = None) -> None:
        SimTaintedData.__init__(self, source)
        self._length = length
        self._maxlen = maxlen

    @property
    def length(self) -> int:
        if self._length is not None:
            return self._length
        else:
            raise UF.CHBError("Tainted string has no length: "
                              + str(self))

    @property
    def maxlen(self) -> int:
        if self._maxlen is not None:
            return self._maxlen
        else:
            raise UF.CHBError("Tainted string has not maxlen: "
                              + str(self))

    @property
    def is_tainted_string(self) -> bool:
        return True

    def has_length(self) -> bool:
        return self._length is not None

    def has_maxlen(self) -> bool:
        return self._maxlen is not None

    def __str__(self) -> str:
        return "tainted-by:" + self.taintsource


class SimTaintedValue(SimTaintedData):

    def __init__(
            self,
            source: str,
            width: int,
            minval: Optional[int] = None,
            maxval: Optional[int] = None) -> None:
        SimTaintedData.__init__(self, source)
        self._width = width    # number of bytes
        self._minval = minval
        self._maxval = maxval

    @property
    def width(self) -> int:
        return self._width

    @property
    def minval(self) -> int:
        if self._minval is not None:
            return self._minval
        else:
            raise UF.CHBError("Tainted value has no minimum value: "
                              + str(self))

    @property
    def maxval(self) -> int:
        if self._maxval is not None:
            return self._maxval
        else:
            raise UF.CHBError("Tainted value has no maximum value: "
                              + str(self))

    def has_minval(self) -> bool:
        return self._minval is not None

    def has_maxval(self) -> bool:
        return self._maxval is not None

    @property
    def is_bounded(self) -> bool:
        return self.has_minval() and self.has_maxval()

    def is_not_equal(self, other: SV.SimValue) -> SV.SimBoolValue:
        if other.is_literal and other.is_defined and self.is_bounded:
            other = cast(SV.SimLiteralValue, other)
            if other.value < self.minval or other.value > self.maxval:
                return SV.simtrue

        self.expressions.append(("SimTaintedValue:" + self.taintsource + " != ",
                                 other))
        return SV.simUndefinedBool

    @property
    def is_tainted_value(self) -> bool:
        return True
