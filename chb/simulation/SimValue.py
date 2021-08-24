# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020-2021 Henny Sipma
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

from abc import ABC, abstractmethod
from typing import cast, List, Tuple

import chb.simulation.SimUtil as SU

import chb.util.fileutil as UF


class SimValue(ABC):
    """Logical representation of a value in a register or memory.

    There are two types of SimValues: a SimLiteralValue and a SimSymbolicValue

    A SimLiteralValue has both a value and a representation as bytes. The value
    is computed from the logical representation as bytes, where the least
    significant byte is byte1. A SimValue representation is independent
    of endianness. The transfer from and to memory addresses ensures
    that bytes are interpreted correctly in accordance with endianness.

    All SimValue subtypes are immutable.

    A SimSymbolicValue does not have a value; it can be an address (e.g.,
    a stackaddress, for which we would not have a concrete value,
    only an offset from some reference point), or a pointer to a constant
    string (e.g., a string returned by getenv or basename), or a symbolic
    value identified by a (meaningful) name (e.g., ra_in, signifying the
    value of the return register passed in at the start of the function).

    At this time SimSymbolicValues can be moved around, but we do not (yet)
    support manipulation of SimSymbolicValues to create symbolic expressions.
    """

    def __init__(self, defined: bool = True) -> None:
        self.defined = defined

    @property
    @abstractmethod
    def width(self) -> int:
        """Returns the number of bits."""

        ...

    @property
    @abstractmethod
    def size(self) -> int:
        """Returns the number of bytes."""

        ...

    @property
    def is_byte(self) -> bool:
        return self.size == 1

    @property
    def is_word(self) -> bool:
        return self.size == 2

    @property
    def is_doubleword(self) -> bool:
        return self.size == 4

    @property
    def is_quadword(self) -> bool:
        return self.size == 8

    @property
    def is_defined(self) -> bool:
        return self.defined

    @property
    def is_undefined(self) -> bool:
        return not self.defined

    @property
    def is_literal(self) -> bool:
        return False

    @property
    def literal_value(self) -> int:
        raise UF.CHBError("Literal-value not supported by " + str(self))

    @property
    def is_symbolic(self) -> bool:
        return False

    @property
    def is_symbolic_return_address(self) -> bool:
        return False

    @property
    def is_function_return_address(self) -> bool:
        return False

    @property
    def is_address(self) -> bool:
        return False

    @property
    def is_file_pointer(self) -> bool:
        return False

    @property
    def is_file_descriptor(self) -> bool:
        return False

    @property
    def is_symbol_table_handle(self) -> bool:
        return False

    @property
    def is_libc_table_address(self) -> bool:
        return False

    @property
    def is_libc_table_value(self) -> bool:
        return False

    @property
    def is_global_address(self) -> bool:
        return False

    @property
    def is_stack_address(self) -> bool:
        return False

    @property
    def is_string_address(self) -> bool:
        return False

    @property
    def is_symbol(self) -> bool:
        return False

    @property
    def is_membyte_link(self) -> bool:
        return False


class SimLiteralValue(SimValue):
    """Superclass of all literal values."""

    def __init__(self, value: int, defined: bool = True) -> None:
        """Value is assumed to be a non-negative integer."""

        SimValue.__init__(self, defined=defined)
        self._value = value

    @property
    def value(self) -> int:
        """Returns non-negative integer value."""

        return self._value

    @property
    def literal_value(self) -> int:
        """Returns non-negative integer value.

        Intended to serve cases where we can't distinguish between literal and
        global address."""

        return self.value

    @property
    def is_literal(self) -> bool:
        return True

    @property
    def is_bool(self) -> bool:
        return False

    @property
    def is_byte(self) -> bool:
        return False

    @property
    def is_word(self) -> bool:
        return False

    @property
    def is_doubleword(self) -> bool:
        return False

    @property
    def is_quadword(self) -> bool:
        return False

    @property
    def is_float(self) -> bool:
        return False

    @property
    def is_zero(self) -> bool:
        return self.is_defined and self.value == 0

    @property
    def is_not_zero(self) -> bool:
        return self.is_defined and self.value != 0

    @property
    def is_negative(self) -> bool:
        return False

    def is_equal(self, other: SimValue) -> "SimBoolValue":
        return simUndefinedBool

    @property
    def is_odd_parity(self) -> bool:
        result = False
        n = self.value
        while n:
            if n & 1:
                result = not result
            n = n >> 1
        return result

    @property
    def leading_zeroes(self) -> "SimDoubleWordValue":
        if self.is_defined:
            x = self.value
            if x == 0:
                r = self.width
            else:
                t = 1 << (self.width - 1)
                r = 0
                while (x & t) == 0:
                    t = t >> 1
                    r = r + 1
            return cast(SimDoubleWordValue, mk_simvalue(r))
        else:
            return simUndefinedDW

    @abstractmethod
    def to_signed_int(self) -> int:
        ...

    @abstractmethod
    def sign_extend(self, size: int) -> "SimLiteralValue":
        ...

    @abstractmethod
    def zero_extend(self, size: int) -> "SimLiteralValue":
        ...

    @property
    @abstractmethod
    def lsb(self) -> int:
        ...

    @property
    @abstractmethod
    def msb(self) -> int:
        ...

    @property
    @abstractmethod
    def msb2(self) -> int:
        ...

    @abstractmethod
    def add(self, other: SimValue) -> "SimLiteralValue":
        ...

    @abstractmethod
    def sub(self, other: SimValue) -> "SimLiteralValue":
        ...

    @abstractmethod
    def mul(self, other: SimValue) -> "SimLiteralValue":
        ...

    @abstractmethod
    def bitwise_and(self, other: SimValue) -> "SimLiteralValue":
        ...

    @abstractmethod
    def bitwise_or(self, other: SimValue) -> "SimLiteralValue":
        ...

    @abstractmethod
    def bitwise_xor(self, other: SimValue) -> "SimLiteralValue":
        ...

    @abstractmethod
    def bitwise_nor(self, other: SimValue) -> "SimLiteralValue":
        ...

    @abstractmethod
    def bitwise_rol(self, other: SimValue) -> "SimLiteralValue":
        ...

    @abstractmethod
    def bitwise_ror(self, other: SimValue) -> "SimLiteralValue":
        ...

    @abstractmethod
    def bitwise_rcl(
            self, other: SimValue, cflag: int) -> Tuple[int, "SimLiteralValue"]:
        ...

    @abstractmethod
    def bitwise_sar(self, other: SimValue) -> Tuple[int, "SimLiteralValue"]:
        ...

    @abstractmethod
    def bitwise_shl(self, other: SimValue) -> Tuple[int, "SimLiteralValue"]:
        ...

    @abstractmethod
    def bitwise_sll(self, shiftamount: int) -> "SimLiteralValue":
        ...

    @abstractmethod
    def bitwise_srl(self, shiftamount: int) -> "SimLiteralValue":
        ...

    def __str__(self) -> str:
        if self.is_defined:
            return str(self.value)
        else:
            return "?"


class SimBoolValue(SimLiteralValue):
    """Single bit value (0 or 1)."""

    def __init__(self, value: int, defined: bool = True) -> None:
        SimLiteralValue.__init__(self, value & 1, defined=defined)

    @property
    def size(self) -> int:
        return 1

    @property
    def width(self) -> int:
        return 1

    @property
    def lsb(self) -> int:
        raise UF.CHBError("Least-significant bit not applicable to SimBoolValue")

    @property
    def msb(self) -> int:
        raise UF.CHBError("Most-significant bit not applicable to SimBoolValue")

    @property
    def msb2(self) -> int:
        raise UF.CHBError(
            "Second most-significant bit not applicable to SimBoolValue")

    @property
    def is_bool(self) -> bool:
        return True

    @property
    def is_set(self) -> bool:
        return self.value > 0

    @property
    def is_true(self) -> bool:
        if self.is_defined:
            return self.value > 0
        else:
            return False

    def is_false(self) -> bool:
        if self.is_defined:
            return self.value == 0
        else:
            return False

    def to_signed_int(self) -> int:
        raise UF.CHBError("To_signed_int not applicable to SimBoolValue")

    def set(self) -> "SimBoolValue":
        return SimBoolValue(1)

    def clear(self) -> "SimBoolValue":
        return SimBoolValue(0)

    def sign_extend(self, size: int) -> SimLiteralValue:
        raise UF.CHBError("Sign-extend not applicable to SimBoolValue")

    def zero_extend(self, size: int) -> SimLiteralValue:
        raise UF.CHBError("Zero-extend not applicable to SimBoolValue")

    def add(self, other: SimValue) -> SimLiteralValue:
        raise UF.CHBError("Addition not applicable to SimBoolValue")

    def sub(self, other: SimValue) -> SimLiteralValue:
        raise UF.CHBError("Subtraction not applicable to SimBoolValue")

    def mul(self, other: SimValue) -> SimLiteralValue:
        raise UF.CHBError("Multiplication not applicable to SimBoolValue")

    def bitwise_and(self, other: SimValue) -> SimLiteralValue:
        raise UF.CHBError("Bitwise and not applicable to SimBoolValue")

    def bitwise_or(self, other: SimValue) -> SimLiteralValue:
        raise UF.CHBError("Bitwise or not applicable to SimBoolValue")

    def bitwise_rol(self, other: SimValue) -> SimLiteralValue:
        raise UF.CHBError("Bitwise rotation not applicable to SimBoolValue")

    def bitwise_ror(self, other: SimValue) -> SimLiteralValue:
        raise UF.CHBError("Bitwise rotation not applicable to SimBoolValue")

    def bitwise_sar(self, other: SimValue) -> Tuple[int, SimLiteralValue]:
        raise UF.CHBError("Bitwise shift not applicable to SimBoolValue")

    def bitwise_rcl(
            self, other: SimValue, cflag: int) -> Tuple[int, SimLiteralValue]:
        raise UF.CHBError("Bitwise rcl not applicable to SimBoolValue")

    def bitwise_shl(self, other: SimValue) -> Tuple[int, SimLiteralValue]:
        raise UF.CHBError("Bitwise shift not applicable to SimBoolValue")

    def bitwise_sll(self, shiftamount: int) -> SimLiteralValue:
        raise UF.CHBError("Bitwise shift not applicable to SimBoolValue")

    def bitwise_srl(self, shiftamount: int) -> SimLiteralValue:
        raise UF.CHBError("Bitwise shift not applicable to SimBoolValue")

    def bitwise_xor(self, other: SimValue) -> SimLiteralValue:
        raise UF.CHBError("Bitwise xor not applicable to SimBoolValue")

    def bitwise_nor(self, other: SimValue) -> SimLiteralValue:
        raise UF.CHBError("Bitwise nor not applicable to SimBoolValue")


class SimByteValue(SimLiteralValue):
    """Single byte value (0-255)."""

    def __init__(self, value: int, defined: bool = True) -> None:
        SimLiteralValue.__init__(self, value & 255, defined=defined)

    @property
    def width(self) -> int:
        return 8

    @property
    def size(self) -> int:
        return 1

    @property
    def lsb(self) -> int:
        """Least significant bit."""

        return self.value % 2

    @property
    def msb(self) -> int:
        """Most significant bit."""

        if self.is_defined:
            return self.value >> 7
        else:
            raise SU.CHBSimValueUndefinedError("SimByteValue.msb")

    @property
    def msb2(self) -> int:
        """Second most significant bit."""

        if self.is_defined:
            return (self.value >> 6) % 2
        else:
            raise SU.CHBSimValueUndefinedError("SimByteValue:msb2")

    @property
    def is_byte(self) -> bool:
        return True

    @property
    def is_link(self) -> bool:
        return False

    @property
    def is_negative(self) -> bool:
        return self.value > 127

    def is_outside_signed_bounds(self, v: int) -> bool:
        return v > 127 or v < -128

    def is_outside_unsigned_bounds(self, v: int) -> bool:
        return v < 0 or v > 255

    def is_equal(self, other: SimValue) -> SimBoolValue:
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            result = 1 if self.value == other.value else 0
            return SimBoolValue(
                result, defined=(self.is_defined and other.is_defined))
        else:
            return SimBoolValue(0, defined=False)

    def add(self, other: SimValue) -> "SimByteValue":
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            newval = (self.value + other.value) % 256
            return SimByteValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedByte

    def add_overflows(self, other: SimLiteralValue) -> bool:
        return self.is_outside_signed_bounds(
            self.to_signed_int() + other.to_signed_int())

    def add_carries(self, other: SimLiteralValue) -> bool:
        return self.is_outside_unsigned_bounds(self.value + other.value)

    def sub(self, other: SimValue) -> "SimByteValue":
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            newval = (self.value - other.value) % 256
            return SimByteValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedByte

    def mul(self, other: SimValue) -> "SimByteValue":
        raise UF.CHBError("Mul not yet implemented for SimByteValue")

    def sub_overflows(self, other: SimLiteralValue) -> bool:
        return self.is_outside_signed_bounds(
            self.to_signed_int() - other.to_signed_int())

    def sub_carries(self, other: SimLiteralValue) -> bool:
        return self.is_outside_unsigned_bounds(self.value - other.value)

    def bitwise_and(self, other: SimValue) -> "SimByteValue":
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            newval = self.value & other.value
            return SimByteValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedByte

    def bitwise_or(self, other: SimValue) -> "SimByteValue":
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            newval = self.value | other.value
            return SimByteValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedByte

    def bitwise_not(self) -> "SimByteValue":
        newval = ~self.value
        return SimByteValue(newval, defined=self.is_defined)

    def bitwise_rol(self, other: SimValue) -> "SimByteValue":
        """Return value rotated left by the value of other % 8."""

        if other.is_literal:
            other = cast(SimLiteralValue, other)
            otherval = other.value % 8
            if otherval == 0:
                return self
            else:
                newval = (self.value << otherval) + (self.value >> (8 - otherval))
                return SimByteValue(
                    newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedByte

    def bitwise_ror(self, other: SimValue) -> "SimByteValue":
        """Return value rotated right by the value of other % 8."""

        if other.is_literal:
            other = cast(SimLiteralValue, other)
            otherval = other.value % 8
            if otherval == 0:
                return self
            else:
                newval = (self.value >> otherval) + (self.value << (8 - otherval))
                return SimByteValue(
                    newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedByte

    def bitwise_rcl(self, other: SimValue, cflag: int) -> Tuple[int, "SimByteValue"]:
        """Return value rotated left with a carry bit by other % 9.

        --- needs a reference.
        """
        SU.checkbit(cflag, "Cflag argument in SimByteValue.bitwise_rcl")
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            otherval = (other.value & 31) % 9
            if otherval == 0:
                return (cflag, self)
            else:
                newval = self.value
                for cnt in range(0, otherval):
                    tempcf = newval >> 7
                    newval = (newval * 2) + cflag
                    cflag = tempcf
                return (cflag,
                        SimByteValue(
                            newval,
                            defined=self.is_defined and other.is_defined))
        else:
            return (0, simUndefinedByte)

    def bitwise_shl(self, other: SimValue) -> Tuple[int, "SimByteValue"]:
        """Return value shifted left by other and the carry flag.

        From x86 shiftleft instruction
        Shifts the bits in the first operand (destination operand) to the left by
        the number of bits specified in the second operand (count operand).
        The count operand can be an immediate value or the CL register. The count
        is masked to 5 bits. Bits shifted beyond the destination operand boundary
        are first shifted into the CF flag, then discarded. At the end of the shift
        operation, the CF flag contains the last bit shifted out of the
        destination operand. For each shift count, the most significant bit of the
        destination operand is shifted into the CF flag, and the least significant
        bit is cleared.

        """

        if other.is_literal:
            other = cast(SimLiteralValue, other)
            otherval = other.value & 31
            if otherval == 0:
                return (-1, self)
            elif otherval > 8:
                return (-1, SimByteValue(0))
            newval = self.value << (otherval - 1)
            msb = newval >> 7
            newval = newval << 1
            return (msb, SimByteValue(
                newval, defined=self.is_defined and other.is_defined))
        return (0, simUndefinedByte)

    def bitwise_shrd(
            self, srcval: SimValue, shift: SimValue) -> Tuple[int, "SimByteValue"]:
        """Return value shifted right by other and the carry flag.

        From x86 shiftrightdouble instruction:
        The instruction shifts the first operand (destination operand) to the
        right the number of bits specified by the third operand (count operand).
        The second operand (source operand) provides bits to shift in from the
        left (starting with the most significant bit of the destination operand).

        The count operand is an unsigned integer that can be stored in an
        immediate byte or the CL register. If the count operand is CL, the shift
        count is the logical AND of CL and a count mask. Ihe width of the count
        mask is 5 bits. Only bits 0 through 4 of the count register are used
        (masking the count to a value between 0 and 31). If the count is greater
        than the operand size, the result is undefined.

        If the count is 1 or greater, the CF flag is filled with the last bit
        shifted out of the destination operand. For a 1-bit shift, the OF
        flag is set if a sign change occurred; otherwise, it is cleared. If
        the count operand is 0, flags are not affected.
        """

        if srcval.is_literal and shift.is_literal:
            srcval = cast(SimLiteralValue, srcval)
            shift = cast(SimLiteralValue, shift)
            shiftvalue = shift.value & 31
            if shiftvalue == 0:
                return (-1, self)
            elif shiftvalue > 8:
                return (-1, SimByteValue(0, defined=True))
            else:
                newvalue = self.value >> (shiftvalue - 1)
                cflag = newvalue % 2
                newvalue = newvalue >> 1
                srcinval = (((srcval.value << (8 - shiftvalue)) >> (8 - shiftvalue))
                            << (8 - shiftvalue))
                newvalue = newvalue + srcinval
                return (
                    cflag,
                    SimByteValue(
                        newvalue,
                        defined=self.is_defined
                        and srcval.is_defined
                        and shift.is_defined))
        else:
            return (0, simUndefinedByte)

    def bitwise_sar(self, other: SimValue) -> Tuple[int, "SimByteValue"]:
        """Return value shifted to the right by other and a carry bit."""

        if other.is_literal:
            other = cast(SimLiteralValue, other)
            otherval = other.value & 31
            if otherval == 0:
                return (-1, self)
            newval = self.value >> (otherval - 1)
            lsb = newval % 2
            newval = newval >> 1
            if self.msb > 0:
                c = ((1 << (otherval + 1)) - 1) << (8 - otherval)
                newval += c
            return (
                lsb,
                SimByteValue(
                    newval, defined=self.is_defined and other.is_defined))
        else:
            return (0, simUndefinedByte)

    def bitwise_sll(self, shiftamount: int) -> "SimByteValue":
        raise UF.CHBError("Bitwise shift left not yet implemented for SimByteValue")

    def bitwise_srl(self, shiftamount: int) -> "SimByteValue":
        raise UF.CHBError("Bitwsise shift right not yet implemented for SimByteValue")

    def bitwise_xor(self, other: SimValue) -> "SimByteValue":
        """Return exclusive or with other value."""

        if other.is_literal:
            other = cast(SimLiteralValue, other)
            newval = self.value ^ other.value
            return SimByteValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedByte

    def bitwise_nor(self, other: SimValue) -> "SimByteValue":
        return self.bitwise_or(other).bitwise_not()

    def to_unsigned_int(self) -> int:
        """Return value if defined."""

        if self.is_defined:
            return self.value
        else:
            raise SU.CHBSimValueUndefinedError('SimByteValue: to_unsigned_int')

    def to_signed_int(self) -> int:
        """Return value interpreted as a signed integer, if defined."""

        if self.is_defined:
            if self.is_negative:
                return self.value - 256
            else:
                return self.value
        else:
            raise SU.CHBSimValueUndefinedError('SimByteValue: to_signed_int')

    def zero_extend(self, size: int) -> SimLiteralValue:
        """Zero extends the byte to a word or doubleword value."""

        if self.is_defined:
            if size == 1:
                return self
            elif size == 2:
                return self.to_word(signextend=False)
            elif size == 4:
                return self.to_doubleword(signextend=False)
            else:
                raise UF.CHBError(
                    "Size for zero-extension not supported: " + str(size))
        else:
            raise SU.CHBSimValueUndefinedError("SimByteValue:zero_extend")

    def sign_extend(self, size: int) -> SimLiteralValue:
        """Sign extends the byte to a word or doubleword value."""

        if self.is_defined:
            if size == 1:
                return self
            elif size == 2:
                return self.to_word(signextend=True)
            elif size == 4:
                return self.to_doubleword(signextend=True)
            else:
                raise UF.CHBError(
                    "Size of sign-extension not supported: " + str(size))
        else:
            raise SU.CHBSimValueUndefinedError("SimByteValue.sign_extend")

    def to_word(self, signextend: bool = True) -> SimLiteralValue:
        if self.is_defined:
            if signextend:
                return SimWordValue(self.to_signed_int())
            else:
                return SimWordValue(self.value)
        else:
            raise SU.CHBSimValueUndefinedError("SimByteValue.to_word")

    def to_doubleword(self, signextend: bool = True) -> SimLiteralValue:
        if self.is_defined:
            if signextend:
                return SimDoubleWordValue(self.to_signed_int())
            else:
                return SimDoubleWordValue(self.value)
        else:
            raise SU.CHBSimValueUndefinedError("SimByteValue.to_doubleword")

    def __str__(self) -> str:
        if self.is_defined:
            return str(self.value)
        else:
            return "?"


class SimWordValue(SimLiteralValue):

    def __init__(
            self,
            value: int,
            defined: bool = True,
            b1defined: bool = True,
            b2defined: bool = True) -> None:
        SimLiteralValue.__init__(self, value & SU.max16, defined=defined)
        self.byte1 = self.value & 255
        self.byte2 = self.value >> 8
        self.b1defined = b1defined and self.defined
        self.b2defined = b2defined and self.defined

    @property
    def size(self) -> int:
        return 2

    @property
    def width(self) -> int:
        return 16

    @property
    def lsb(self) -> int:
        """Least significant bit."""

        if self.is_defined:
            return self.value % 2
        else:
            raise SU.CHBSimValueUndefinedError("SimWordValue:lsb")

    @property
    def msb(self) -> int:
        """Most significant bit."""

        if self.is_defined:
            return (self.value >> 15)
        else:
            raise SU.CHBSimValueUndefinedError("SimWordValue:msb")

    @property
    def msb2(self) -> int:
        """Second most significant bit."""

        if self.is_defined:
            return (self.value >> 14) % 2
        else:
            raise SU.CHBSimValueUndefinedError("SimWordValue:msb2")

    @property
    def lowbyte(self) -> SimByteValue:
        return SimByteValue(self.byte1, self.b1defined)

    @property
    def highbyte(self) -> SimByteValue:
        return SimByteValue(self.byte2, self.b2defined)

    @property
    def is_word(self) -> bool:
        return True

    @property
    def is_negative(self) -> bool:
        if self.is_defined:
            return self.value > SU.max15
        else:
            raise SU.CHBSimValueUndefinedError('SimWordValue: is_negative')

    def outside_signed_bounds(self, v: int) -> bool:
        return v > SU.max15 or v < -(SU.max15 + 1)

    def outside_unsigned_bounds(self, v: int) -> bool:
        return v > SU.max16 or v < 0

    def add(self, other: SimValue) -> "SimWordValue":
        if other.is_literal:
            other = cast(SimWordValue, other)
            newval = (self.value + other.value) % (SU.max16 + 1)
            return SimWordValue(newval, self.is_defined and other.is_defined)
        else:
            return simUndefinedWord

    def sub(self, other: SimValue) -> "SimWordValue":
        if other.is_literal:
            other = cast(SimWordValue, other)
            newval = (self.value - other.value) % (SU.max16 + 1)
            return SimWordValue(newval, self.is_defined and other.is_defined)
        else:
            return simUndefinedWord

    def mul(self, other: SimValue) -> "SimWordValue":
        raise UF.CHBError("Mul not yet implemented for SimWordValue")

    def add_overflows(self, other: SimValue) -> bool:
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            return self.outside_signed_bounds(
                self.to_signed_int() + other.to_signed_int())
        else:
            raise UF.CHBError("SimWordValue.add_overflows: other is not a literal: "
                              + str(other))

    def add_carries(self, other: SimValue) -> bool:
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            return self.outside_unsigned_bounds(self.value + other.value)
        else:
            raise UF.CHBError("SimWordValue.add_carries: other is not a literal: "
                              + str(other))

    def bitwise_and(self, other: SimValue) -> "SimWordValue":
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            newval = (self.value & other.value)
            return SimWordValue(newval, self.is_defined and other.is_defined)
        else:
            return simUndefinedWord

    def bitwise_or(self, other: SimValue) -> "SimWordValue":
        raise UF.CHBError("Bitwise or not yet implemented for SimWordValue")

    def bitwise_nor(self, other: SimValue) -> "SimWordValue":
        raise UF.CHBError("Bitwise nor not yet implemented for SimWordValue")

    def bitwise_xor(self, other: SimValue) -> "SimWordValue":
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            newval = self.value ^ other.value
            return SimWordValue(newval, self.is_defined and other.is_defined)
        else:
            return simUndefinedWord

    def bitwise_rol(self, other: SimValue) -> "SimWordValue":
        raise UF.CHBError("Bitwise rotation not yet implemented for SimWordValue")

    def bitwise_ror(self, other: SimValue) -> "SimWordValue":
        raise UF.CHBError("Bitwise rotation not yet implemented for SimWordValue")

    def bitwise_shl(self, other: SimValue) -> Tuple[int, "SimWordValue"]:
        raise UF.CHBError("Bitwise shift not yet implemented for SimWordValue")

    def bitwise_sar(self, other: SimValue) -> Tuple[int, "SimWordValue"]:
        raise UF.CHBError("Bitwise shift not yet implemented for SimWordValue")

    def bitwise_sll(self, shiftamount: int) -> "SimWordValue":
        raise UF.CHBError("Bitwise shift left not yet implemented for SimWordValue")

    def bitwise_srl(self, shiftamount: int) -> "SimWordValue":
        raise UF.CHBError("Bitwise shift right not yet implemented for SimWordValue")

    def bitwise_rcl(
            self, other: SimValue, cflag: int) -> Tuple[int, "SimWordValue"]:
        raise UF.CHBError("Bitwise rcl not yet implemented for SimWordValue")

    def zero_extend(self, size: int) -> SimLiteralValue:
        """Zero extends word to doubleword value."""

        if self.is_defined:
            if size == 2:
                return self
            elif size == 4:
                return self.to_doubleword(signextend=False)
            else:
                raise UF.CHBError('Size for zero-extension not supported: '
                                  + str(size))
        else:
            raise SU.CHBSimValueUndefinedError('SimWordValue:zero_extend')

    def sign_extend(self, size: int) -> SimLiteralValue:
        """Sign extends to a doubleword."""

        if self.is_defined:
            if size == 2:
                return self
            elif size == 4:
                return self.to_doubleword(signextend=True)
            else:
                raise UF.CHBError("Size of sign extension not supported: "
                                  + str(size))
        else:
            raise SU.CHBSimValueUndefinedError('SimWordValue.sign_extend')

    def to_doubleword(self, signextend: bool = True) -> "SimDoubleWordValue":
        if self.is_defined:
            if signextend:
                return SimDoubleWordValue(self.to_signed_int())
            else:
                return SimDoubleWordValue(self.value)
        else:
            raise SU.CHBSimValueUndefinedError('SimWordValue.to_doubleword')

    def to_double_size(self, highval: "SimWordValue") -> "SimDoubleWordValue":
        if self.is_defined and highval.is_defined:
            newval = self.value + (highval.value << 16)
            return SimDoubleWordValue(newval)
        else:
            return simUndefinedDW

    def to_unsigned_int(self) -> int:
        if self.is_defined:
            return self.value
        else:
            raise SU.CHBSimValueUndefinedError('SimWordValue: to_unsigned_int')

    def to_signed_int(self) -> int:
        if self.is_defined:
            if self.is_negative:
                return self.value - (SU.max16 + 1)
            else:
                return self.value
        else:
            raise SU.CHBSimValueUndefinedError('SimWordValue: to_signed_int')

    def to_hex(self) -> str:
        if self.is_defined:
            return hex(self.value)
        else:
            raise SU.CHBSimValueUndefinedError('SimWordValue: to_hex')


class SimDoubleWordValue(SimLiteralValue):

    def __init__(
            self,
            value: int,
            defined: bool = True,
            b1defined: bool = True,
            b2defined: bool = True,
            b3defined: bool = True,
            b4defined: bool = True) -> None:
        SimLiteralValue.__init__(self, value & SU.max32, defined=defined)
        self._byte1 = self.value & 255
        self._byte2 = (self.value >> 8) & 255
        self._byte3 = (self.value >> 16) & 255
        self._byte4 = (self.value >> 24) & 255
        self.b1defined = b1defined and self.is_defined
        self.b2defined = b2defined and self.is_defined
        self.b3defined = b3defined and self.is_defined
        self.b4defined = b4defined and self.is_defined

    @property
    def width(self) -> int:
        return 32

    @property
    def size(self) -> int:
        return 4

    @property
    def lsb(self) -> int:
        """Return least significant bit."""

        if self.is_defined:
            return self.value % 2
        else:
            raise SU.CHBSimValueUndefinedError("SimDoubleWordValue:lsb")

    @property
    def msb(self) -> int:
        """Return most significant bit."""

        if self.is_defined:
            return self.value >> 31
        else:
            raise SU.CHBSimValueUndefinedError("SimDoubleWordValue:msb")

    @property
    def msb2(self) -> int:
        """Return second most significant bit."""

        if self.is_defined:
            return (self.value >> 30) % 2
        else:
            raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:get_msb2')

    @property
    def byte1(self) -> int:
        """Return value of least significant byte."""

        return self._byte1

    @property
    def byte2(self) -> int:
        return self._byte2

    @property
    def byte3(self) -> int:
        return self._byte3

    @property
    def byte4(self) -> int:
        return self._byte4

    @property
    def simbyte1(self) -> SimByteValue:
        """Return least significant byte."""

        return SimByteValue(self._byte1, defined=self.b1defined)

    @property
    def simbyte2(self) -> SimByteValue:
        return SimByteValue(self._byte2, defined=self.b2defined)

    @property
    def simbyte3(self) -> SimByteValue:
        return SimByteValue(self._byte3, defined=self.b3defined)

    @property
    def simbyte4(self) -> SimByteValue:
        return SimByteValue(self._byte4, defined=self.b4defined)

    @property
    def lowword(self) -> SimWordValue:
        """Return the lowest two bytes."""

        return SimWordValue(
            (self.byte2 << 8) + self.byte1,
            defined=self.b1defined and self.b2defined)

    @property
    def highword(self) -> SimWordValue:
        """Return the highest two bytes."""

        return SimWordValue(
            (self.byte4 << 8) + self.byte3,
            defined=self.b3defined and self.b4defined)

    @property
    def highhalf(self) -> SimWordValue:
        return self.highword

    @property
    def lowhalf(self) -> SimWordValue:
        return self.lowword

    @property
    def is_doubleword(self) -> bool:
        return True

    @property
    def is_positive(self) -> bool:
        if self.is_defined:
            return self.value <= SU.max31 and self.value > 0
        else:
            return False

    @property
    def is_negative(self) -> bool:
        if self.is_defined:
            return self.value > SU.max31
        else:
            return False

    @property
    def is_non_negative(self) -> bool:
        if self.is_defined:
            return self.value <= SU.max31
        else:
            return False

    @property
    def is_non_positive(self) -> bool:
        if self.is_defined:
            return self.value == 0 or self.is_negative
        else:
            return False

    def outside_signed_bounds(self, v: int) -> bool:
        return v > SU.max31 or v < -(SU.max31 + 1)

    def outside_unsigned_bounds(self, v: int) -> bool:
        return v > SU.max32 or v < 0

    def set_low_word(self, w: SimValue) -> "SimDoubleWordValue":
        if w.is_literal:
            w = cast(SimLiteralValue, w)
            if w.is_word:
                newval = w.value + ((self.value >> 16) << 16)
                return SimDoubleWordValue(newval,
                                          self.is_defined and w.is_defined)
            else:
                raise SU.CHBSimOpError("set word", [self, w])
        else:
            raise SU.CHBSimValueUndefinedError(
                "SimDoubleWordValue.set_low_word " + str(self))

    def set_byte1(self, b: SimByteValue) -> "SimDoubleWordValue":
        newval = SU.compute_dw_value(
            b.value, self.byte2, self.byte3, self.byte4)
        newdefined = (
            b.is_defined
            and self.b2defined
            and self.b3defined
            and self.b4defined)
        return SimDoubleWordValue(
            newval,
            defined=newdefined,
            b1defined=not b.is_defined,
            b2defined=self.b2defined,
            b3defined=self.b3defined,
            b4defined=self.b4defined)

    def set_byte2(self, b: SimByteValue) -> "SimDoubleWordValue":
        newval = SU.compute_dw_value(self.byte1, b.value, self.byte3, self.byte4)
        newdefined = (
            self.b1defined
            and b.is_defined
            and self.b3defined
            and self.b4defined)
        return SimDoubleWordValue(
            newval,
            defined=newdefined,
            b1defined=self.b1defined,
            b2defined=b.is_defined,
            b3defined=self.b3defined,
            b4defined=self.b4defined)

    def set_byte3(self, b: SimByteValue) -> "SimDoubleWordValue":
        newval = SU.compute_dw_value(self.byte1, self.byte2, b.value, self.byte4)
        newdefined = (
            self.b1defined
            and self.b2defined
            and b.is_defined
            and self.b4defined)
        return SimDoubleWordValue(
            newval,
            defined=newdefined,
            b1defined=self.b1defined,
            b2defined=self.b2defined,
            b3defined=b.is_defined,
            b4defined=self.b4defined)

    def set_byte4(self, b: SimByteValue) -> "SimDoubleWordValue":
        newval = SU.compute_dw_value(self.byte1, self.byte2, self.byte3, b.value)
        newdefined = (
            self.b1defined
            and self.b2defined
            and self.b3defined
            and b.is_defined)
        return SimDoubleWordValue(
            newval,
            defined=newdefined,
            b1defined=self.b1defined,
            b2defined=self.b2defined,
            b3defined=self.b3defined,
            b4defined=b.is_defined)

    def is_equal(self, other: SimValue) -> SimBoolValue:
        """Return a true BoolValue if both values are equal."""

        if other.is_literal:
            other = cast(SimBoolValue, other)
            result = 1 if self.value == other.value else 0
            return SimBoolValue(
                result, defined=self.is_defined and other.is_defined)
        else:
            raise SU.CHBSimValueUndefinedError(
                "SimDoubleWordValue:is_equal " + str(other))

    def is_not_equal(self, other: SimValue) -> SimBoolValue:
        """Return a true BoolValue if both values are not equal."""

        if other.is_literal:
            other = cast(SimBoolValue, other)
            result = 1 if self.value != other.value else 0
            return SimBoolValue(result, self.is_defined and other.is_defined)
        raise SU.CHBSimValueUndefinedError(
            "SimDoubleWordValue:is_not_equal " + str(other))

    def add(self, other: SimValue) -> "SimDoubleWordValue":
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            newval = (self.value + other.value) % (SU.max32 + 1)
            return SimDoubleWordValue(
                newval, defined=self.is_defined and other.is_defined)
        raise SU.CHBSimValueUndefinedError("SimDoubleWordValue:add " + str(other))

    def add_int(self, v: int) -> "SimDoubleWordValue":
        return SimDoubleWordValue(self.value + v, defined=self.is_defined)

    def add_overflows(self, other: SimValue) -> bool:
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            return self.outside_signed_bounds(
                self.to_signed_int() + other.to_signed_int())
        else:
            raise UF.CHBError("SimDoubleWordValue.add_overflows: "
                              + "other is not a literal: "
                              + str(other))

    def add_carries(self, other: SimValue) -> bool:
        if other.is_literal:
            other = cast(SimLiteralValue, other)
            return self.outside_unsigned_bounds(self.value + other.value)
        else:
            raise UF.CHBError("SimDoubleWordValue.add_carries: "
                              + "other is not a literal: "
                              + str(other))

    def sub(self, other: SimValue) -> "SimDoubleWordValue":
        """Signed subtraction."""

        if other.is_literal:
            other = cast(SimLiteralValue, other)
            newval = (self.value - other.value) % (SU.max32 + 1)
            return SimDoubleWordValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            raise SU.CHBSimValueUndefinedError(
                "SimDoubleWordValue:sub " + str(other))

    def subu(self, other: SimValue) -> "SimDoubleWordValue":
        """Unsigned subtraction."""

        if other.is_literal:
            other = cast(SimLiteralValue, other)
            newval = (self.value - other.value) % (SU.max32 + 1)
            return SimDoubleWordValue(
                newval, defined=self.is_defined and other.is_defined)

        # need to investigate use of inverted stack
        # -----------------------------------------
        # elif other.is_stack_address() and self.value == 0:
        #    return mk_simbasevalue(
        #             "invertedstack",65536 - other.get_offset_value())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:subu ' + str(other))

    def sub_overflows(self, other: SimLiteralValue) -> bool:
        return self.outside_signed_bounds(
            self.to_signed_int() - other.to_signed_int())

    def sub_carries(self, other: SimLiteralValue) -> bool:
        return self.outside_unsigned_bounds(self.value - other.value)

    def mul(self, other: SimValue) -> "SimQuadWordValue":
        """Signed multiplication into quadword.

        --- need to check implementation.
        """

        if other.is_literal and other.is_doubleword:
            other = cast("SimDoubleWordValue", other)
            newval = self.value * other.value
            return SimQuadWordValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedQW

    def divu(self, other: SimLiteralValue) -> "SimDoubleWordValue":
        """Unsigned division."""

        if other.value > 0:
            newval = self.value // other.value
            return SimDoubleWordValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            raise SU.CHBSimValueUndefinedError(
                "SimDoubleWordValue:div " + str(other))

    def modu(self, other: SimLiteralValue) -> "SimDoubleWordValue":
        """Unsigned modulo."""

        if other.value > 0:
            newval = self.value % other.value
            return SimDoubleWordValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            raise SU.CHBSimValueUndefinedError(
                "SimDoubleWordValue:mod " + str(other))

    def bitwise_and(self, other: SimValue) -> "SimDoubleWordValue":
        if other.is_literal and other.is_doubleword:
            other = cast("SimDoubleWordValue", other)
            newval = (self.value & other.value)
            return SimDoubleWordValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedDW

    def bitwise_or(self, other: SimValue) -> "SimDoubleWordValue":
        if other.is_literal and other.is_doubleword:
            other = cast("SimDoubleWordValue", other)
            newval = (self.value | other.value)
            return SimDoubleWordValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedDW

    def bitwise_nor(self, other: SimValue) -> "SimDoubleWordValue":
        return self.bitwise_or(other).bitwise_not()

    def bitwise_not(self) -> "SimDoubleWordValue":
        return SimDoubleWordValue(-(self.value+1), defined=self.is_defined)

    def bitwise_xor(self, other: SimValue) -> "SimDoubleWordValue":
        if other.is_literal and other.is_doubleword:
            other = cast("SimDoubleWordValue", other)
            newval = self.value ^ other.value
            return SimDoubleWordValue(
                newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedDW

    def bitwise_rol(self, other: SimValue) -> "SimDoubleWordValue":
        """Rotate left by other value."""

        if other.is_literal and other.is_doubleword:
            other = cast("SimDoubleWordValue", other)
            otherval = other.value % 32
            if otherval == 0:
                return self
            else:
                newval = (self.value << otherval) + (self.value >> (32 - otherval))
                return SimDoubleWordValue(
                    newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedDW

    def bitwise_ror(self, other: SimValue) -> "SimDoubleWordValue":
        """Rotate right by other value."""

        if other.is_literal and other.is_doubleword:
            other = cast("SimDoubleWordValue", other)
            otherval = other.value % 32
            if otherval == 0:
                return self
            else:
                newval = (self.value >> otherval) + (self.value << (32-otherval))
                return SimDoubleWordValue(
                    newval, defined=self.is_defined and other.is_defined)
        else:
            return simUndefinedDW

    def bitwise_rcl(
            self,
            other: SimValue,
            cflag: int) -> Tuple[int, "SimDoubleWordValue"]:
        """Rotate left, incorporating the carry flag."""

        if other.is_literal and other.is_doubleword:
            other = cast("SimDoubleWordValue", other)
            otherval = other.value & 31
            if otherval == 0:
                return (cflag, self)
            else:
                newval = self.value
                for cnt in range(0, otherval):
                    tempcf = newval >> 31
                    newval = (newval * 2) + cflag
                    cflag = tempcf
                return (
                    cflag,
                    SimDoubleWordValue(
                        newval,
                        defined=self.is_defined and other.is_defined))
        else:
            return(0, simUndefinedDW)

    def bitwise_shrd(
            self,
            srcval: SimLiteralValue,
            shift: SimLiteralValue) -> Tuple[int, "SimDoubleWordValue"]:
        """Shift right double using the carry flag.

        --- needs checking.
        """

        shiftval = shift.value & 31
        if shiftval == 0:
            return (-1, self)
        else:
            newval = self.value >> (shiftval - 1)
            cflag = newval % 2
            newval = newval >> 1
            srcinval = (
                ((srcval.value << (32 - shiftval)) >> (32 - shiftval))
                << (32 - shiftval))
            newval = newval + srcinval
            return (
                cflag,
                SimDoubleWordValue(
                    newval,
                    defined=(self.is_defined
                             and srcval.is_defined
                             and shift.is_defined)))

    def bitwise_shld(
            self,
            srcval: SimLiteralValue,
            shift: SimLiteralValue) -> Tuple[int, "SimDoubleWordValue"]:
        """Shift left double using the carry flag.

        --- needs checking.
        """

        shiftval = shift.value & 31
        if shiftval == 0:
            return (-1, self)
        else:
            newval = self.value << (shiftval - 1)
            cflag = newval % 2
            newval = newval << 1
            srcinval = srcval.value >> (32 - shiftval)
            newval = newval + srcinval
            return (
                cflag,
                SimDoubleWordValue(
                    newval,
                    defined=(self.is_defined
                             and srcval.is_defined
                             and shift.is_defined)))

    def bitwise_shl(
            self, other: SimValue) -> Tuple[int, "SimDoubleWordValue"]:
        """Shift left by other value, and return carry flag."""

        if other.is_literal and other.is_doubleword:
            other = cast("SimDoubleWordValue", other)
            otherval = other.value & 31
            if otherval == 0:
                return (-1, self)
            else:
                newval = self.value << (otherval - 1)
                msb = newval >> 31
                newval = newval << 1
                return (
                    msb,
                    SimDoubleWordValue(
                        newval, defined=self.is_defined and other.is_defined))
        else:
            return (0, simUndefinedDW)

    def bitwise_sll(self, shiftamount: int) -> "SimDoubleWordValue":
        """Shift left by an integer amount."""

        shiftamount = shiftamount % 32
        if shiftamount == 0:
            return self
        else:
            newval = self.value << shiftamount
            return SimDoubleWordValue(newval, defined=self.is_defined)

    def bitwise_shr(
            self, other: SimLiteralValue) -> Tuple[int, "SimDoubleWordValue"]:
        """Shift right by other value."""

        otherval = other.value & 31
        if otherval == 0:
            return (-1, self)
        else:
            newval = self.value >> (otherval - 1)
            lsb = newval % 2
            newval = newval >> 1
            return (
                lsb,
                SimDoubleWordValue(
                    newval,
                    defined=self.is_defined and other.is_defined))

    def bitwise_sar(
            self, other: SimValue) -> Tuple[int, "SimDoubleWordValue"]:
        """Arithmetic shift right by other value."""

        if other.is_doubleword and other.is_literal:
            other = cast("SimDoubleWordValue", other)
            otherval = other.value & 31
            if otherval == 0:
                return (-1, self)
            else:
                newval = self.value >> (otherval - 1)
                lsb = newval % 2
                newval = newval >> 1
                if self.msb > 0:
                    c = ((1 << (otherval + 1)) - 1) << (32 - otherval)
                    newval += c
                return (
                    lsb,
                    SimDoubleWordValue(
                        newval, defined=self.is_defined and other.is_defined))
        else:
            return (0, simUndefinedDW)

    def bitwise_sra(self, shift: int) -> "SimDoubleWordValue":
        """Arithmetic shift right by an integer value.

        --- todo: properly handle negative values.
        """

        if shift == 0:
            return self
        else:
            newval = self.value >> shift
            return SimDoubleWordValue(newval, defined=self.is_defined)

    def bitwise_srl(self, shift: int) -> "SimDoubleWordValue":
        """Logical shift right by an integer value."""

        shift = shift % 32
        if shift == 0:
            return self
        else:
            newval = self.value >> shift
            return SimDoubleWordValue(newval, defined=self.is_defined)

    def zero_extend(self, size: int) -> SimLiteralValue:
        if size == 4:
            return self
        elif size == 8:
            return SimQuadWordValue(self.value)
        else:
            raise UF.CHBError(
                "Zero extension to size "
                + str(size)
                + " not supported for SimDoubleWordValue")

    def sign_extend(self, size: int) -> SimLiteralValue:
        raise UF.CHBError(
            "Sign extension not yet implemented for SimDoubleWordValue")

    def to_doubleword(self, signextend: bool = True) -> "SimDoubleWordValue":
        return self

    def to_double_size(self, highval: "SimDoubleWordValue") -> "SimQuadWordValue":
        if self.is_defined and highval.is_defined:
            newval = self.value + (highval.value << 32)
            return SimQuadWordValue(newval)
        else:
            return simUndefinedQW

    def to_unsigned_int(self) -> int:
        if self.is_defined:
            return self.value
        else:
            raise SU.CHBSimValueUndefinedError(
                "SimDoubleWordValue:to_unsigned_int")

    def to_signed_int(self) -> int:
        if self.is_defined:
            if self.is_negative:
                return self.value - (SU.max32 + 1)
            else:
                return self.value
        else:
            raise SU.CHBSimValueUndefinedError(
                "SimDoubleWordValue:to_signed_int")

    def __str__(self) -> str:
        if self.is_defined:
            pb1 = "b1:" + str(self.byte1) if self.b1defined else "b1:?"
            pb2 = "b2:" + str(self.byte2) if self.b2defined else "b2:?"
            pb3 = "b3:" + str(self.byte3) if self.b3defined else "b3:?"
            pb4 = "b4:" + str(self.byte4) if self.b4defined else "b4:?"
            if not (self.b1defined and self.b2defined
                    and self.b3defined and self.b4defined):
                return "[" + pb1 + "; " + pb2 + "; " + pb3 + "; " + pb4 + "]"
            else:
                return str(hex(self.value))
        else:
            return "?"


class SimQuadWordValue(SimLiteralValue):

    def __init__(self, value: int, defined: bool = True) -> None:
        SimLiteralValue.__init__(self, value & SU.max64, defined)

    @property
    def width(self) -> int:
        return 64

    @property
    def size(self) -> int:
        return 8

    @property
    def lowhalf(self) -> SimDoubleWordValue:
        """Return the low doubleword value."""

        return SimDoubleWordValue(self.value & SU.max32, self.is_defined)

    @property
    def highhalf(self) -> SimDoubleWordValue:
        """Return the high doubleword value."""

        return SimDoubleWordValue(self.value >> 32, self.is_defined)

    @property
    def lsb(self) -> int:
        """Return least-significant bit."""

        if self.is_defined:
            return self.value % 2
        else:
            raise SU.CHBSimValueUndefinedError("SimQuadWordValue:lsb")

    @property
    def msb(self) -> int:
        """Return most-significant bit."""

        if self.is_defined:
            return (self.value >> 63)
        else:
            raise SU.CHBSimValueUndefinedError("SimQuadWordValue:msb")

    @property
    def msb2(self) -> int:
        """Return second most-significant bit."""

        if self.is_defined:
            return (self.value >> 62) % 2
        else:
            raise SU.CHBSimValueUndefinedError("SimQuadWordValue.msb2")

    def add(self, other: SimValue) -> "SimQuadWordValue":
        raise UF.CHBError("Addition not yet implemented for QuadWordValue")

    def sub(self, other: SimValue) -> "SimQuadWordValue":
        raise UF.CHBError("Subtraction not yet implemented for QuadWordValue")

    def mul(self, other: SimValue) -> "SimQuadWordValue":
        raise UF.CHBError("Multiplication not yet implemented for QuadWordValue")

    def bitwise_and(self, other: SimValue) -> "SimQuadWordValue":
        raise UF.CHBError("Bitwise and not yet implemented for QuadWordValue")

    def bitwise_or(self, other: SimValue) -> "SimQuadWordValue":
        raise UF.CHBError("Bitwise or not yet implemented for QuadWordValue")

    def bitwise_rol(self, other: SimValue) -> "SimQuadWordValue":
        raise UF.CHBError("Bitwise rotation not yet implemented for QuadWordValue")

    def bitwise_ror(self, other: SimValue) -> "SimQuadWordValue":
        raise UF.CHBError("Bitwise rotation not yet implemented for QuadWordValue")

    def bitwise_sar(self, other: SimValue) -> Tuple[int, "SimQuadWordValue"]:
        raise UF.CHBError("Bitwise shift not yet implemented for QuadWordValue")

    def bitwise_shl(self, other: SimValue) -> Tuple[int, "SimQuadWordValue"]:
        raise UF.CHBError("Bitwise shift not yet implemented for QuadWordValue")

    def bitwise_sll(self, shiftamount: int) -> "SimQuadWordValue":
        raise UF.CHBError("Bitwise shift left not yet implemented for QuadWordValue")

    def bitwise_srl(self, shiftamount: int) -> "SimQuadWordValue":
        raise UF.CHBError("Bitwise shift right not yet implemented for QuadWordValue")

    def bitwise_rcl(
            self, other: SimValue, cflag: int) -> Tuple[int, "SimQuadWordValue"]:
        raise UF.CHBError("Bitwise rcl not yet implemented for QuadWordValue")

    def bitwise_xor(self, other: SimValue) -> "SimQuadWordValue":
        raise UF.CHBError("Bitwise xor not yet implemented for QuadWordValue")

    def bitwise_nor(self, other: SimValue) -> "SimQuadWordValue":
        raise UF.CHBError("Bitwise nor not yet implemented for QuadWordValue")

    def sign_extend(self, size: int) -> SimLiteralValue:
        if size == 8:
            return self
        else:
            raise UF.CHBError(
                "Sign extend with size "
                + str(size)
                + " not supported for SimQuadWordValue")

    def zero_extend(self, size: int) -> SimLiteralValue:
        if size == 8:
            return self
        else:
            raise UF.CHBError(
                "Zero extend with size "
                + str(size)
                + " not supported for SimQuadWordValue")

    @property
    def is_quadword(self) -> bool:
        return True

    @property
    def is_negative(self) -> bool:
        if self.is_defined:
            return self.value > SU.max63
        else:
            return False

    def to_signed_int(self) -> int:
        if self.is_defined:
            if self.is_negative:
                return self.value - (SU.max64 + 1)
            else:
                return self.value
        else:
            raise SU.CHBSimValueUndefinedError(
                "SimQuadWordValue.to_signed_int")

    def __str__(self) -> str:
        if self.is_defined:
            return str(hex(self.value))
        else:
            return "?"


class SimFloatValue(SimValue):

    def __init__(self, value: float, defined: bool = True) -> None:
        SimValue.__init__(self, defined=defined)
        self._value = value

    @property
    def value(self) -> float:
        return self._value

    @property
    def width(self) -> int:
        return 32

    @property
    def size(self) -> int:
        return 4

    @property
    def is_float(self) -> bool:
        return True

    def is_not_equal(self, other: "SimFloatValue") -> SimBoolValue:
        if other.is_defined:
            if other.value == self.value:
                return SimBoolValue(0)
            else:
                return SimBoolValue(1)
        else:
            raise SU.CHBSimValueUndefinedError(
                "SimFloatValue.is_not_equal: " + str(other))

    def bitwise_srl(self, shift: int) -> SimDoubleWordValue:
        if shift == 31:
            if self.value >= 0.0:
                return cast(SimDoubleWordValue, mk_simvalue(0, size=4))
            else:
                return cast(SimDoubleWordValue, mk_simvalue(1, size=4))
        else:
            raise SU.CHBSimValueUndefinedError(
                "SimFloatValue.bitwise_srl: " + str(shift))


def compose_simvalue(bytes: List[SimByteValue]) -> SimLiteralValue:
    """Returns a byte, word, or doubleword, depending on the number of bytes."""

    if len(bytes) == 1:
        return bytes[0]
    elif len(bytes) == 2:
        b1 = bytes[0]
        b2 = bytes[1]
        if b1.is_defined and b2.is_defined:
            return SimWordValue((b2.value << 8) + b1.value)
        else:
            return SimWordValue(0, defined=False)
    elif len(bytes) == 4:
        b1 = bytes[0]
        b2 = bytes[1]
        b3 = bytes[2]
        b4 = bytes[3]
        if (
                b1.is_defined
                and b2.is_defined
                and b3.is_defined
                and b4.is_defined):
            bval = SU.compute_dw_value(b1.value, b2.value, b3.value, b4.value)
            return SimDoubleWordValue(bval)
        else:
            return SimDoubleWordValue(0, defined=False)
    else:
        raise UF.CHBError('Number of bytes not supported: ' + str(len(bytes)))


# convenience functions

def mk_simvalue(value: int, size: int = 4) -> SimLiteralValue:
    if size == 1:
        return SimByteValue(value)
    elif size == 2:
        return SimWordValue(value)
    elif size == 4:
        return SimDoubleWordValue(value)
    else:
        raise UF.CHBError('Size of value not supported: ' + str(size))


def mk_simbytevalue(value: int) -> SimByteValue:
    return cast(SimByteValue, mk_simvalue(value, size=1))


def mk_simcharvalue(c: str) -> SimByteValue:
    return mk_simbytevalue(ord(c))


def mk_floatvalue(value: float) -> SimFloatValue:
    return SimFloatValue(value)


def mk_undefined_simvalue(size: int) -> SimLiteralValue:
    if size == 1:
        return simUndefinedByte
    elif size == 2:
        return simUndefinedWord
    elif size == 4:
        return simUndefinedDW
    else:
        raise UF.CHBError('Size of undefined value not supported: ' + str(size))


# constant SimValue's

simflagset = SimBoolValue(1)
simflagclr = SimBoolValue(0)
simflagundef = SimBoolValue(0, defined=False)

simtrue = SimBoolValue(1)
simfalse = SimBoolValue(0)
simUndefinedBool = SimBoolValue(0, defined=False)

simUndefinedByte = SimByteValue(0, defined=False)
simUndefinedWord = SimWordValue(0, defined=False)
simUndefinedDW = SimDoubleWordValue(0, defined=False)
simUndefinedQW = SimQuadWordValue(0, defined=False)

simZerobyte = SimByteValue(0)
simZero = SimDoubleWordValue(0)
simOne = SimDoubleWordValue(1)
simNegOne = SimDoubleWordValue(-1)
