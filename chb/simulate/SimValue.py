# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
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

import chb.util.fileutil as UF
import chb.simulate.SimUtil as SU


class SimValue(object):
    """Logical representation of a value in a register or memory.

    There are two types of SimValues: a SimLiteralValue and a SimSymbolicValue

    A SimLiteralValue has both a value and a representation as bytes. The value
    is computed from the logical representation as bytes, where the least
    significant byte is byte1. A SimValue representation is independent
    of endianness. The transfer from and to memory addresses ensures
    that bytes are interpreted correctly in accordance with endianness.

    A SimBaseValue has a partial value. It consists of a symbolic base and
    a one-, or two-bytes offset that can be subjected to arithmetic and
    bitwise operations. A SimBaseValue, in contrast with a SimBaseAddress,
    is not an address. A SimBaseValue maye be the result of some (generally
    disallowed) operations on addresses. Examples are the result of complementing
    a stack address to extract alignment information.

    A SimSymbolicValue does not have a value; it can be an address (e.g.,
    a stackaddress, for which we would not have a concrete value,
    only an offset from some reference point), or a pointer to a constant
    string (e.g., a string returned by getenv or basename), or a symbolic
    value identified by a (meaningful) name (e.g., ra_in, signifying the
    value of the return register passed in at the start of the function).

    At this time SimSymbolicValues can be moved around, but we do not (yet)
    support manipulation of SimSymbolicValues to create symbolic expressions.
    """

    def __init__(self,defined=True):
        self.defined = defined

    def is_defined(self): return self.defined

    def is_literal(self): return False
    def is_symbolic(self): return False
    def is_address(self): return False
    def is_string_address(self): return False
    def is_symbol(self): return False

    def get_width(self): return 0    # number of bits
    def get_size(self): return 0     # number of bytes

class SimLiteralValue(SimValue):

    def __init__(self,value,defined=True):
        SimValue.__init__(self,defined=defined)
        self.value = value              # non-negative integer

    def is_literal(self): return True

    def is_bool(self): return False
    def is_byte(self): return False
    def is_word(self): return False
    def is_doubleword(self): return False
    def is_float(self): return False

    def is_zero(self): return self.is_defined() and self.value == 0

    def is_not_zero(self): return self.is_defined() and self.value != 0

    def is_odd_parity(self):
        result = False
        n = self.value
        while n:
            if n & 1: result = not result
            n = n >> 1
        return result
    
    def __str__(self):
        if self.is_defined():
            return str(self.value)
        else:
            return '?'

class SimBaseValue(SimValue):

    def __init__(self,base,value,bytecount=2,defined=True):
        SimValue.__init__(self,defined=defined)
        self.base = base
        self.bytecount = bytecount
        if bytecount == 1:
            self.value = value & 255
        else:
            self.value = value & 65535
            self.byte1 = self.value & 255
            self.byte2 = self.value >> 8

    def bitwise_and(self,other):
        if other.is_literal():
            if other.value < self.value:
                newval = self.value & other.value
                return mk_simvalue(newval)
            else:
                return mk_simbasevalue('unknown',self.value & other.value)
        else:
            return SimUndefinedDW

    def __str__(self):
        return '[[' + self.base + ']]:' + str(self.value)



class SimBoolValue(SimLiteralValue):
    """Single bit value (0 or 1)."""

    def __init__(self,value,defined=True):
        SimLiteralValue.__init__(self,value & 1,defined=defined)

    def is_bool(self): return True

    def is_set(self): return self.value > 0

    def is_true(self): return self.value > 0

    def get_size(self): return 1

    def set(self): return SimBoolValue(1)

    def clear(self): return SimBoolValue(0)


class SimByteValue(SimLiteralValue):
    """Single byte value (0-255)."""

    def __init__(self,value,defined=True):
        SimLiteralValue.__init__(self,value & 255,defined=defined)

    def get_width(self): return 8
    def get_size(self): return 1

    def is_byte(self): return True

    def is_negative(self): return self.value > 127

    def outside_signed_bounds(self,v): return v > 127 or v < -128

    def outside_unsigned_bounds(self,v): return v < 0 or v > 255

    def is_equal(self,other):
        if other.is_literal():
            result = 1 if self.value == other.value else 0
            return SimBoolValue(result,defined=(self.is_defined() and other.is_defined()))
        return SimBoolValue(0,defined=False)

    def add(self,other):
        if other.is_literal():
            newval = (self.value + other.value) % 256
            return SimByteValue(newval,defined=self.is_defined() and other.is_defined())
        return simUndefinedByte

    def add_overflows(self,other):
        return self.outside_signed_bounds(self.to_signed_int() + other.to_signed_int())

    def add_carries(self,other):
        return self.outside_unsigned_bounds(self.value + other.value)

    def sub(self,other):
        if other.is_literal():
            newval = (self.value + other.value) % 256
            return SimByteValue(newval,defined=self.is_defined() and other.is_defined())
        return simUndefinedByte

    def sub_overflows(self,other):
        return self.outside_signed_bounds(self.to_signed_int() - other.to_signed_int())

    def sub_carries(self,other):
        return self.outside_unsigned_bounds(self.value - other.value)
        
    def bitwise_and(self,other):
        if other.is_literal():
            newval = self.value & other.value
            return SimByteValue(newval,defined=self.is_defined() and other.is_defined())


    def bitwise_or(self,other):
        if other.is_literal():
            newval = self.value | other.value
            return SimByteValue(newval,defined=self.is_defined() and other.is_defined())
        return simUndefinedByte

    def bitwise_not(self):
        newval = ~self.value
        return SimByteValue(newval,defined=self.is_defined())

    def bitwise_rol(self,other):
        if other.is_literal():
            otherval = other.value % 8
            if otherval == 0: return self
            newval = (self.value << otherval) + (self.value >> (8 - otherval))
            return SimByteValue(newval,defined=self.is_defined() and other.is_defined())
        return simUndefinedByte

    def bitwise_ror(self,other):
        if other.is_liter():
            otherval = other.value % 8
            if otherval == 0: return self
            newval = (self.value >> otherval) + (self.value << (8 - otherval))
            return SimByteValue(newval,defined=self.is_defined() and other.is_defined())
        return simUndefinedByte

    def bitwise_rcl(self,other,cflag):
        if other.is_literal():
            otherval = (other.value & 31) % 9
            if otherval == 0: return (cflag,self)
            newval = self.value
            for cnt in range(0,otherval):
                tempcf = newval >> 7
                newval = (newval * 2) + cflag
                cflag = tempcf
            return (cflag,SimByteValue(newval,defined=self.is_defined() and other.is_defined()))
        return (0,simUndefinedByte)

    def bitwise_shl(self,other):
        if other.is_literal():
            otherval = other.value & 31
            if otherval == 0: return (None,self)
            if otherval > 8:
                return (None,SimByteValue(0))
            newval = self.value << (otherval - 1)
            msb = newval >> 7
            newval = newval << 1
            return (msb,SimByteValue(newval,defined=self.is_defined() and other.is_defined()))
        return (0,simUndefinedByte)

    def bitwise_shrd(self,srcval,shift):
        shiftval = shift.value  & 31
        if shiftval == 0: return (None,self)
        if shiftval > 8:
            return (None,SimByteValue(0,undefined=True))
        newval = self.value >> (shiftval - 1)
        cflag = newval % 2
        newval = newval >> 1
        srcinval = ((srcval.value << (8 - shiftval)) >> (8 - shiftval)) << (8 - shiftval)
        newval = newval + srcinval
        return (cflag,SimByteValue(newval,defined=self.is_defined() and other.is_defined()))

    def bitwise_sar(self,other):
        if other.is_literal():
            otherval = other.value & 31
            if otherval == 0: return (None,self)
            newval = self.value >> (otherval - 1)
            lsb = newval % 2
            newval = newval >> 1
            if self.get_msb() > 0:
                c = ((1 << (otherval + 1)) - 1) << (8 - otherval)
                newval += c
            return (lsb,SimByteValue(newval,defined=self.is_defined() and other.is_defined()))
        return (0,simUndefinedByte)

    def bitwise_xor(self,other):
        if other.is_literal():
            newval = self.value ^ other.value
            return SimByteValue(newval,defined=self.is_defined() and other.is_defined())
        return simUndefinedByte

    def get_lbs(self): return self.value % 2     # least significant bit

    def get_msb(self): return self.value >> 7    # most sigificant bit

    def to_unsigned_int(self):
        if self.is_defined():
            return self.value
        else:
            raise SU.SimValueUndefinedError('SimByteValue: to_unsigned_int')

    def to_signed_int(self):
        if self.is_defined():
            if self.is_negative():
                return self.value - 256
            else:
                return self.value
        else:
            raise SU.SimValueUndefinedError('SimByteValue: to_signed_int')

    def zero_extend(self,size):
        if self.is_defined():
            if size == 1: return self
            if size == 2: return self.to_word(signextend=False)
            if size == 4: return self.to_doubleword(signextend=False)
            raise UF.CHBError('Size for zero-extension not supported: ' + str(size))
        raise SU.CHBSimValueUndefinedError('SimByteValue:zero_extend')

    def sign_extend(self,size):
        if self.is_defined():
            if size == 1: return self
            if size == 2: return self.to_word(signextend=True)
            if size == 4: return self.to_doubleword(signextend=True)
            raise UF.CHBError('Size of sign-extension not supported: ' + str(size))
        raise SU.CHBSimValueUndefinedError('SimByteValue.sign_extend')

    def to_word(self,signextend=True):
        if self.is_defined():
            if signextend:
                return SimWordValue(self.to_signed_int())
            else:
                return SimWordValue(self.value)
        raise SU.CHBSimValueUndefinedError('SimByteValue.to_word')

    def to_doubleword(self,signextend=True):
        if self.is_defined():
            if signextend:
                return SimDoubleWordValue(self.to_signed_int())
            else:
                return SimDoubleWordValue(self.value)
        raise SU.CHBSimValueUndefinedError('SimByteValue.to_doubleword')

    def __str__(self):
        if self.is_defined():
            return str(self.value)
        else:
            return '?'
            

class SimWordValue(SimLiteralValue):

    def __init__(self,value,defined=True,b1defined=True,b2defined=True):
        SimLiteralValue.__init__(self,value & SU.max16,defined=defined)
        self.byte1 = self.value & 255
        self.byte2 = self.value >> 8
        self.b1defined = b1defined and self.defined
        self.b2defined = b2defined and self.defined

    def is_word(self): return True
    def get_width(self): return 16
    def get_size(self): return 2

    def is_negative(self):
        if self.is_defined():
            return self.value > SU.max15
        else:
            return SU.CHBSimValueUndefinedError('SimWordValue: is_negative')

    def outside_signed_bounds(self,v): return v > SU.max15 or v < -(SU.max15 + 1)

    def outside_unsigned_bounds(self,v): return v > SU.max16 or v < 0

    def sign_extend(self,size):
        if self.is_defined():
            if size == 2: return self
            if size == 4: return self.to_doubleword(signextend=True)
            raise UF.CHBError('Size of sign extension not supported: ' + str(size))
        raise SU.CHBSimValueUndefinedError('SimWordValue.sign_extend')

    def add(self,other):
        if other.is_literal():
            newval = (self.value + other.value) % (SU.max16 + 1)
            return SimWordValue(newval,self.is_defined() and other.is_defined())
        return SimUndefinedWord

    def add_overflows(self,other):
        return self.outside_signed_bounds(self.to_signed_int() + other.to_signed_int())

    def add_carries(self,other):
        return self.outside_unsigned_bounds(self.value + other.value)

    def bitwise_and(self,other):
        if other.is_literal():
            newval = (self.value & other.value)
            return SimWordValue(newval,self.is_defined() and other.is_defined())
        return SimUndefinedWord

    def bitwise_xor(self,other):
        if other.is_literal():
            newval = self.value ^ other.value
            return SimWordValue(newval,self.undefined or other.undefined)
        return SimUndefinedWord

    def get_low_byte(self):
        return SimByteValue(self.byte1,self.b1defined)

    def get_high_byte(self):
        return SimByteValue(self.byte2,self.b2defined)

    def zero_extend(self,size):
        if self.is_defined():
            if size == 2: return self
            if size == 4: return self.to_doubleword(signextend=False)
            raise UF.CHBError('Size for zero-extension not supported: ' + str(size))
        raise SU.CHBSimValueUndefinedError('SimWordValue:zero_extend')

    def to_doubleword(self,signextend=True):
        if self.is_defined():
            if signextend:
                return SimDoubleWordValue(self.to_signed_int())
            else:
                return SimDoubleWordValue(self.value)
        raise SU.CHBSimValueUndefinedError('SimWordValue.to_doubleword')

    def to_unsigned_int(self):
        if self.is_defined():
            return self.value
        else:
            raise CHBSimValueUndefinedError('SimWordValue: to_unsigned_int')

    def to_signed_int(self):
        if self.is_defined():
            if self.is_negative():
                return self.value - (SU.max16 + 1)
            else:
                return self.value
        else:
            raise CHBSimValueUndefinedError('SimWordValue: to_signed_int')

    def to_hex(self):
        if self.is_defined():
            return hex(self.value)
        else:
            raise CHBSimValueUndefinedError('SimWordValue: to_hex')


class SimDoubleWordValue(SimLiteralValue):

    def __init__(self,value,defined=True,
                     b1defined=True,b2defined=True,b3defined=True,b4defined=True):
        SimLiteralValue.__init__(self,value & SU.max32,defined=defined)
        self.byte1 = self.value & 255
        self.byte2 = (self.value >> 8) & 255
        self.byte3 = (self.value >> 16) & 255
        self.byte4 = (self.value >> 24) & 255     
        self.b1defined = b1defined and self.is_defined()
        self.b2defined = b2defined and self.is_defined()
        self.b3defined = b3defined and self.is_defined()
        self.b4defined = b4defined and self.is_defined()

    def is_doubleword(self): return True
    def get_width(self): return 32     # bit width
    def get_size(self): return 4       # number of bytes

    def is_positive(self):
        if self.is_defined():
            return self.value <= SU.max31 and self.value > 0
        else:
            raise CHBSimValueUndefinedError('SimDoubleWordValue: is_positive')

    def is_negative(self):
        if self.is_defined():
            return self.value > SU.max31
        else:
            raise CHBSimValueUndefinedError('SimDoubleWordValue: is_negative')

    def is_non_negative(self):
        if self.is_defined():
            return self.value <= SU.max31
        else:
            raise CHBSimValueUndefinedError('SimDoubleWordValue: is_non_negative')

    def is_non_positive(self):
        if self.is_defined():
            return self.value == 0 or self.is_negative()
        else:
            raise CHBSimValueUndefinedError('SimDoubleWordValue: is_non_positive')

    def outside_signed_bounds(self,v): return v > SU.max31 or v < -(SU.max31 + 1)

    def outside_unsigned_bounds(self,v): return v > SU.max32 or v < 0

    def set_low_word(self,w):
        if w.is_defined():
            if w.is_word():
                newval = w.value + ((self.value >> 16) << 16)
                return SimDoubleWordValue(newval,self.is_defined())
            raise SU.CHBSimOpError('set word', [ self, w ])
        else:
            return simundefinedDW

    def set_byte1(self,b1):
        if b1.is_byte():
            newval = SU.compute_dw_value(b1.value,self.byte2,self.byte3,self.byte4)
            newdefined = b1.is_defined() and self.b2defined and self.b3defined and self.b4defined
            return SimDoubleWordValue(newval,
                                      defined=newdefined,
                                      b1defined=not b1.is_defined(),
                                      b2defined=self.b2defined,
                                      b3defined=self.b3defined,
                                      b4defined=self.b4defined)
        raise SU.CHBSimOpError('set byte1', [ self, b1 ])

    def set_byte2(self,b2):
        if b2.is_byte():
            newval = SU.compute_dw_value(self.byte1,b2.value,self.byte3,self.byte4)
            newdefined = self.b1defined and b2.is_defined() and self.b3defined and self.b4defined
            return SimDoubleWordValue(newval,
                                      defined=newdefined,
                                      b1defined=self.b1defined,
                                      b2defined=b2.is_defined(),
                                      b3defined=self.b3defined,
                                      b4defined=self.b4defined)
        raise SU.CHBSimOpError('set byte2', [ self, b2 ])

    def set_byte3(self,b3):
        if b3.is_byte():
            newval = SU.compute_dw_value(self.byte1,self.byte2,b3.value,self.byte4)
            newdefined = self.b1defined and self.b2defined and b3.is_defined() and self.b4defined
            return SimDoubleWordValue(newval,
                                      defined=newdefined,
                                      b1defined=self.b1defined,
                                      b2defined=self.b2defined,
                                      b3defined=b3.is_defined(),
                                      b4defined=self.b4defined)
        raise SU.CHBSimOpError('set byte3', [ self, b3 ])

    def set_byte4(self,b4):
        if b4.is_byte():
            newval = SU.compute_dw_value(self.byte1,self.byte2,self.byte3,b4.value)
            newdefined = self.b1defined and self.b2defined and self.b3defined and b4.is_defined()
            return SimDoubleWordValue(newval,
                                      defined=newdefined,
                                      b1defined=self.b1defined,
                                      b2defined=self.b2defined,
                                      b3defined=self.b3defined,
                                      b4defined=b4.is_defined())
        raise SU.CHBSimOpError('set byte4', [ self, b4 ])

    def is_equal(self,other):
        if other.is_literal():
            result = 1 if self.value == other.value else 0
            return SimBoolValue(result,defined=self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:is_equal ' + str(other))

    def is_not_equal(self,other):
        if other.is_literal():
            result = 1 if self.value != other.value else 0
            return SimBoolValue(result,self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:is_not_equal ' + str(other))

    def add(self,other):
        if other.is_literal():
            newval = (self.value + other.value) % (SU.max32 + 1)
            return SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:add ' + str(other))

    def add_overflows(self,other):
        return self.outside_signed_bounds(self.to_signed_int() + other.to_signed_int())

    def add_carries(self,other):
        return self.outside_unsigned_bounds(self.value + other.value)

    def sub(self,other):
        if other.is_literal():
            newval = (self.value - other.value) % (SU.max32 + 1)
            return SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:sub ' + str(other))

    def subu(self,other):
        if other.is_literal():
            newval = (self.value - other.value) % (SU.max32 + 1)
            return SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined())
        elif other.is_stack_address() and self.value == 0:
            return mk_simbasevalue('invertedstack',65536 - other.get_offset_value())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:subu ' + str(other))

    def sub_overflows(self,other):
        return self.outside_signed_bounds(self.to_signed_int() - other.to_signed_int())

    def sub_carries(self,other):
        return self.outside_unsigned_bounds(self.value - other.value)

    def mul(self,other):
        if other.is_literal():
            newval = self.value * other.value
            return SimQuadWordValue(newval,defined=self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:mul ' + str(other))

    def divu(self,other):
        if other.is_literal() and other.value > 0:
            newval = self.value // other.value
            return SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:div ' + str(other))

    def modu(self,other):
        if other.is_literal() and other.value > 0:
            newval = self.value % other.value
            return SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:mod ' + str(other))

    def bitwise_and(self,other):
        if other.is_literal():
            newval = (self.value & other.value)
            return SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:bitwise_and ' + str(other))

    def bitwise_or(self,other):
        if other.is_literal():
            newval = (self.value | other.value)
            return SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:bitwise_or ' + str(other))

    def bitwise_nor(self,other):
        if other.is_literal():
            try:
                orvalue = self.bitwise_or(other)
                return orvalue.bitwise_not()
            except SU.CHBSimValueUndefinedError as e:
                raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:bitwise_nor ' + str(other)
                                                   + ': ' + str(e))

    def bitwise_not(self):
        return SimDoubleWordValue(-(self.value+1),defined=self.is_defined())

    def bitwise_xor(self,other):
        if other.is_literal():
            newval = self.value ^ other.value
            return SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:bitwise_xor ' + str(other))

    def bitwise_rol(self,other):
        if other.is_literal():
            otherval = other.value % 32
            if otherval == 0: return self
            newval = (self.value << otherval) + (self.value >> (32-otherval))
            return SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue.bitwise_rol ' + str(other))

    def bitwise_ror(self,other):
        if other.is_literal():
            otherval = other.value % 32
            if otherval == 0: return self
            newval = (self.value >> otherval) + (self.value << (32-otherval))
            return SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined())
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue.bitwise_ror ' + str(other))

    def bitwise_rcl(self,other,cflag):
        if other.is_literal():
            otherval = other.value & 31
            if otherval == 0: return (cflag,self)
            newval = self.value
            for cnt in range(0,otherval):
                tempcf = newval >> 31
                newval = (newval * 2) + cflag
                cflag = tempcf
                return (cflag,SimDoubleWordValue(newval,
                                                 defined=self.is_defined() and other.is_defined()))
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue.bitwise_rcl ' + str(other))

    def bitwise_shrd(self,srcval,shift):
        if srcval.is_literal() and shift.is_literal():
            shiftval = shift.value & 31
            if shiftval == 0: return (None,self)
            newval = self.value >> (shiftval - 1)
            cflag = newval % 2
            newval = newval >> 1
            srcinval = ((srcval.value << (32 - shiftval)) >> (32 - shiftval)) << (32 - shiftval)
            newval = newval + srcinval
            return (cflag,SimDoubleWordValue(newval,
                                             defined=(self.is_defined()
                                                      and srcval.is_defined()
                                                      and shift.is_defined())))
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue.bitwise_shrd ' + str(other))

    def bitwise_shld(self,srcval,shift):
        if srcval.is_literal() and shift.is_literal():
            shiftval = shift.value & 31
            if shiftval == 0: return (None,self)
            newval = self.value << (shiftval - 1)
            cflag = newval % 2
            newval = newval << 1
            srcinval = srcval.value >> (32 - shiftval)
            newval = newval + srcinval
            return (cflag,SimDoubleWordValue(newval,
                                             defined=(self.is_defined()
                                                      and srcval.is_defined()
                                                      and shift.is_defined())))
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue.bitwise_shld ' + str(other))

    def bitwise_shl(self,other):
        if other.is_literal():
            otherval = other.value & 31
            if otherval == 0: return (None,self)
            newval = self.value << (otherval - 1)
            msb = newval >> 31
            newval = newval << 1
            return (msb,SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined()))
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue.bitwise_shl ' + str(other))

    def bitwise_sll(self,shiftamount):
        shiftamount = shiftamount % 32
        if shiftamount == 0: return self
        newval = self.value << shiftamount
        return SimDoubleWordValue(newval,defined=self.is_defined())

    def bitwise_shr(self,other):
        if other.is_literal():
            otherval = other.value & 31
            if otherval == 0: return (None,self)
            newval = self.value >> (otherval - 1)
            lsb = newval % 2
            newval = newval >> 1
            return (lsb,SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined()))
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue.bitwise_shr ' + str(other))

    def bitwise_sar(self,other):
        if other.is_literal():
            otherval = other.value & 31
            if otherval == 0: return (None,self)
            newval = self.value >> (otherval - 1)
            lsb = newval % 2
            newval = newval >> 1
            if self.get_msb() > 0:
                c = ((1 << (otherval + 1)) - 1) << (32 - otherval)
                newval += c
            return (lsb,SimDoubleWordValue(newval,defined=self.is_defined() and other.is_defined()))
        raise SU.CHBSimValueUndefinedError('SimDoubleWordValue.bitwise_sar ' + str(other))

    def bitwise_sra(self,shift):
        if shift == 0:
            return self
        newval = self.value >> shift   # Todo: properly handle negative values
        return SimDoubleWordValue(newval,defined=self.is_defined())

    def bitwise_srl(self,shift):
        shift = shift % 32
        if shift == 0:
            return self
        newval = self.value >> shift
        return SimDoubleWordValue(newval,defined=self.is_defined())

    def get_lsb(self):   # least significant bit
        if self.is_defined():
            return self.value % 2
        else:
            raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:get_lsb')

    def get_msb(self):    # most sigificant bit
        if self.is_defined():
            return self.value >> 31
        else:
            raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:get_msb')

    def get_msb2(self):   # 2nd most significant bit
        if self.is_defined():
            return (self.value >> 30) % 4
        else:
            raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:get_msb2')

    def get_byte1(self): return SimByteValue(self.byte1,defined=self.b1defined)

    def get_byte2(self): return SimByteValue(self.byte2,defined=self.b2defined)

    def get_byte3(self): return SimByteValue(self.byte3,defined=self.b3defined)

    def get_byte4(self): return SimByteValue(self.byte4,defined=self.b4defined)

    def get_low_word(self):
        return SimWordValue((self.byte2 << 8) + self.byte1,
                            defined=self.b1defined and self.b2defined)

    def get_low_half(self): return get_low_word()

    def get_high_half(self):
        return SimWordValue((self.byte4 << 8) + self.byte3,
                            defined=self.b3defined and self.b4defined)

    def to_doubleword(self,signextend=True): return self

    def to_unsigned_int(self):
        if self.is_defined():
            return self.value
        else:
            raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:to_unsigned_int')

    def to_signed_int(self):
        if self.is_defined():
            if self.is_negative():
                return self.value - (SU.max32 + 1)
            else:
                return self.value
        else:
            raise SU.CHBSimValueUndefinedError('SimDoubleWordValue:to_signed_int')
        
    def __str__(self):
        if self.is_defined():
            pb1 = 'b1:' + str(self.byte1) if self.b1defined else 'b1:?'
            pb2 = 'b2:' + str(self.byte2) if self.b2defined else 'b2:?'
            pb3 = 'b3:' + str(self.byte3) if self.b3defined else 'b3:?'
            pb4 = 'b4:' + str(self.byte4) if self.b4defined else 'b4:?'
            if not (self.b1defined and self.b2defined
                    and self.b3defined and self.b4defined):
                return '[' + pb1 + '; ' + pb2 + '; ' + pb3 + '; ' + pb4 + ']'
            else:
                return str(hex(self.value))
        else:
            return '?'

class SimQuadWordValue(SimLiteralValue):

    def __init__(self,value,undefined=False):
        SimLiteralValue.__init__(self,value & SU.max64,undefined)

    def get_low_half(self):
        return SimDoubleWordValue(self.value & SU.max32,self.undefined)

    def get_high_half(self):
        return SimDoubleWordValue(self.value >> 32,self.undefined)

    def __str__(self):
        if self.undefined: return '?'
        return str(hex(self.value))


def compose_simvalue(bytes):
    for b in bytes:
        if not check_byte(b):
            raise UF.CHBError('One of the bytes is not a literal value: '
                              + ','.join(str(b) for b in bytes))
    if len(bytes) == 1:
        return  bytes[0]
    elif len(bytes) == 2:
        b1 = bytes[0]
        b2 = bytes[1]
        if b1.is_defined() and b2.is_defined():
            return SimWordValue((b2.value << 8) + b1.value)
        else:
            return SimWordValue(0,defined=False)
    elif len(bytes) == 4:
        b1 = bytes[0]
        b2 = bytes[1]
        b3 = bytes[2]
        b4 = bytes[3]
        if b1.is_defined() and b2.is_defined() and b3.is_defined() and b4.is_defined():
            bval = SU.compute_dw_value(b1.value,b2.value,b3.value,b4.value)
            return SimDoubleWordValue(bval)
        else:
            return SimDoubleWordValue(0,defined=False)
    else:
        raise UF.CHBError('Number of bytes not supported: ' + str(len(bytes)))

class SimFloatValue(SimLiteralValue):

    def __init__(self,value):
        SimLiteralValue.__init__(self,value)

    def is_float(self): return True

    def is_not_equal(self,other):
        if other.is_literal() and other.is_defined():
            if other.value == self.value:
                return SimBoolValue(0)
            else:
                return SimBoolValue(1)
        raise CHBSimValueUndefinedError('SimFloatValue.is_not_equal: ' + str(other))

    def count_leading_zeros(self):
        return 1

    def bitwise_srl(self,value):
        if value == 31:
            if self.value >= 0.0:
                return mk_simvalue(0)
            else:
                return mk_simvalue(1)
        raise CHBSimValueUndefinedError('SimFloatValue.bitwise_srl: ' + str(value))


# convenience functions

def mk_simvalue(value,size=4):
    if size == 1:
        return SimByteValue(value)
    elif size == 2:
        return SimWordValue(value)
    elif size == 4:
        return SimDoubleWordValue(value)
    else:
        raise CHBError('Size of value not supported: ' + str(size))

def mk_simbytevalue(value):
    return mk_simvalue(value,size=1)

def mk_simcharvalue(c):
    return mk_simbytevalue(ord(c))

def mk_floatvalue(value):
    return SimFloatValue(value)

def mk_undefined_simvalue(size):
    if size == 1:
        return simUndefinedByte
    elif size == 2:
        return simUndefinedWord
    elif size == 4:
        return simUndefinedDW
    else:
        raise CHBError('Size of undefined value not supported: ' + str(size))

def mk_simbasevalue(base,value): return SimBaseValue(base,value)

def check_byte(b):
    return b.is_literal() and b.is_byte()
                                            
# constant SimValue's

simflagset = SimBoolValue(1)
simflagclr = SimBoolValue(0)
simflagundef = SimBoolValue(0,defined=False)

simtrue = SimBoolValue(1)
simfalse = SimBoolValue(0)
simUndefinedBool = SimBoolValue(0,defined=False)

simUndefinedByte = SimByteValue(0,defined=False)
simUndefinedWord = SimWordValue(0,defined=False)
simUndefinedDW = SimDoubleWordValue(0,defined=False)
simZerobyte = SimByteValue(0)
simZero = SimDoubleWordValue(0)
simOne = SimDoubleWordValue(1)
simNegOne = SimDoubleWordValue(-1)

