# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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

    def __init__(self,value,undefined=False,symbolic=None):
        self.value = value
        self.undefined = undefined
        self.symbolic = symbolic

    def is_address(self): return False
    def is_bool(self): return False
    def is_byte(self): return False
    def is_word(self): return False
    def is_doubleword(self): return False

    def is_zero(self): return self.value == 0

    def get_width(self): return 0

    def is_odd_parity(self):
        result = False
        n = self.value
        while n:
            if n & 1: result = not result
            n = n >> 1
        return result

    def __eq__(self,other):
        return (self.value == other.value
                    and self.undefined == other.undefined)

    def __ne__(self,other):
        return (self.value != other.value
                    or self.undefined != other.undefined)
    
    def __str__(self):
        if self.undefined:
            return '?'
        else:
            return str(self.value)


class SimBoolValue(SimValue):

    def __init__(self,value,undefined=False):
        SimValue.__init__(self,value & 1,undefined)

    def is_bool(self): return True

    def is_set(self): return self.value > 0

    def get_width(self): return 1

    def set(self): return SimBoolValue(1)

    def clear(self): return SimBoolValue(0)

    def __str__(self):
        if self.undefined: return '?'
        else: return str(self.value)

class SimByteValue(SimValue):

    def __init__(self,value,undefined=False):
        SimValue.__init__(self,value & 255,undefined)

    def get_width(self): return 8

    def is_byte(self): return True

    def is_negative(self): return self.value > 127

    def outside_signed_bounds(self,v): return v > 127 or v < -128

    def outside_unsigned_bounds(self,v): return v < 0 or v > 255

    def add(self,other):
        newval = (self.value + other.value) % 256
        return SimByteValue(newval,self.undefined or other.undefined)

    def add_overflows(self,other):
        return self.outside_signed_bounds(self.to_signed_int() + other.to_signed_int())

    def add_carries(self,other):
        return self.outside_unsigned_bounds(self.value + other.value)

    def sub(self,other):
        newval = (self.value + other.value) % 256
        return SimByteValue(newval,self.undefined or other.undefined)

    def sub_overflows(self,other):
        return self.outside_signed_bounds(self.to_signed_int() - other.to_signed_int())

    def sub_carries(self,other):
        return self.outside_unsigned_bounds(self.value - other.value)
        
    def bitwise_and(self,other):
        newval = self.value & other.value
        return SimByteValue(newval,self.undefined or other.undefined)

    def bitwise_or(self,other):
        newval = self.value | other.value
        return SimByteValue(newval,self.undefined or other.undefined)

    def bitwise_not(self):
        newval = ~self.value
        return SimByteValue(newval,self.undefined)

    def bitwise_rol(self,other):
        otherval = other.value % 8        
        if otherval == 0: return self
        newval = (self.value << otherval) + (self.value >> (8 - otherval))
        return SimByteValue(newval,self.undefined or other.undefined)

    def bitwise_ror(self,other):
        otherval = other.value % 8
        if otherval == 0: return self
        newval = (self.value >> otherval) + (self.value << (8 - otherval))
        return SimByteValue(newval,self.undefined or other.undefined)

    def bitwise_rcl(self,other,cflag):
        otherval = (other.value & 31) % 9
        if otherval == 0: return (cflag,self)
        newval = self.value
        for cnt in range(0,otherval):
            tempcf = newval >> 7
            newval = (newval * 2) + cflag
            cflag = tempcf
        return (cflag,SimByteValue(newval,self.undefined or other.undefined))

    def bitwise_shl(self,other):
        otherval = other.value & 31
        if otherval == 0: return (None,self)
        if otherval > 8:
            return (None,SimByteValue(0))
        newval = self.value << (otherval - 1)
        msb = newval >> 7
        newval = newval << 1
        return (msb,SimByteValue(newval,self.undefined or other.undefined))

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
        return (cflag,SimByteValue(newval,self.undefined or srcval.undefined or shift.undefined))        

    def bitwise_sar(self,other):
        otherval = other.value & 31
        if otherval == 0: return (None,self)
        newval = self.value >> (otherval - 1)
        lsb = newval % 2
        newval = newval >> 1
        if self.get_msb() > 0:
            c = ((1 << (otherval + 1)) - 1) << (8 - otherval)
            newval += c
        return (lsb,SimByteValue(newval,self.undefined or other.undefined))

    def bitwise_xor(self,other):
        newval = self.value ^ other.value
        return SimByteValue(newval,self.undefined or other.undefined)

    def get_lbs(self): return self.value % 2     # least significant bit

    def get_msb(self): return self.value >> 7    # most sigificant bit

    def to_unsigned_int(self): return self.value

    def to_signed_int(self):
        if self.is_negative():
            return self.value - 256
        else:
            return self.value

    def zero_extend(self,size):
        if size == 1: return self
        if size == 2: return self.to_word(signextend=False)
        if size == 4: return self.to_doubleword(signextend=False)
        raise UF.CHBError('Size for zero-extension not supported: ' + str(size))

    def sign_extend(self,size):
        if size == 1: return self
        if size == 2: return self.to_word(signextend=True)
        if size == 4: return self.to_doubleword(signextend=True)
        raise UF.CHBError('Size of sign-extension not supported: ' + str(size))

    def to_word(self,signextend=True):
        if signextend:
            return SimWordValue(self.to_signed_int(),self.undefined)
        else:
            return SimWordValue(self.value,self.undefined)

    def to_doubleword(self,signextend=True):
        if signextend:
            return SimDoubleWordValue(self.to_signed_int(),self.undefined)
        else:
            return SimDoubleWordValue(self.value,self.undefined)
            

class SimWordValue(SimValue):
    def __init__(self,value,undefined=False,b1defined=True,b2defined=True):
        SimValue.__init__(self,value & SU.max16,undefined)
        self.byte1 = self.value & 255    # lsf byte
        self.byte2 = self.value >> 8     # msf byte
        self.b1defined = b1defined and (not self.undefined)
        self.b2defined = b2defined and (not self.undefined)

    def is_word(self): return True

    def is_negative(self): return self.value > SU.max15

    def outside_signed_bounds(self,v): return v > SU.max15 or v < -(SU.max15 + 1)

    def outside_unsigned_bounds(self,v): return v > SU.max16 or v < 0

    def add(self,other):
        newval = (self.value + other.value) % (SU.max16 + 1)
        return SimWordValue(newval,self.undefined or other.undefined)

    def add_overflows(self,other):
        return self.outside_signed_bounds(self.to_signed_int() + other.to_signed_int())

    def add_carries(self,other):
        return self.outside_unsigned_bounds(self.value + other.value)

    def bitwise_and(self,other):
        newval = (self.value & other.value)
        return SimWordValue(newval,self.undefined or other.undefined)

    def bitwise_xor(self,other):
        newval = self.value ^ other.value
        return SimWordValue(newval,self.undefined or other.undefined)

    def get_width(self): return 16

    def get_low_byte(self): return SimByteValue(self.byte1,self.undefined)

    def get_high_byte(self): return SimByteValue(self.byte2,self.undefined)

    def to_unsigned_int(self): return self.value

    def to_signed_int(self):
        if self.is_negative():
            return self.value - (SU.max16 + 1)
        else:
            return self.value

    def to_hex(self): return hex(self.value)

class SimDoubleWordValue(SimValue):

    def __init__(self,value,undefined=False,
                     b1defined=True,b2defined=True,b3defined=True,b4defined=True,
                     symbolic=None):
        SimValue.__init__(self,value & SU.max32,undefined,symbolic)
        self.byte1 = self.value & 255               # lowest (lsf) byte
        self.byte2 = (self.value >> 8) & 255
        self.byte3 = (self.value >> 16) & 255
        self.byte4 = (self.value >> 24) & 255       # highest (msf) byte
        self.b1defined = b1defined and (not self.undefined)
        self.b2defined = b2defined and (not self.undefined)
        self.b3defined = b3defined and (not self.undefined)
        self.b4defined = b4defined and (not self.undefined)

    def is_doubleword(self): return True

    def is_negative(self): return self.value > SU.max31

    def get_width(self): return 32

    def outside_signed_bounds(self,v): return v > SU.max31 or v < -(SU.max31 + 1)

    def outside_unsigned_bounds(self,v): return v > SU.max32 or v < 0

    def set_word(self,w):
        if w.is_word():
            newval = w.value + ((self.value >> 16) << 16)
            return SimDoubleWordValue(newval,undefined=self.undefined or w.undefined)
        raise SU.CHBSimOpError('set word', [ self, w ])

    def set_low_byte(self,b1):
        if b1.is_byte():
            newval = SU.compute_dw_value(b1.value,self.byte2,self.byte3,self.byte4)
            return SimDoubleWordValue(newval,b1defined=True,b2defined=self.b2defined,
                                          b3defined=self.b3defined,b4defined=self.b4defined)
        raise SU.CHBSimOpError('set low byte', [ self, b1 ])

    def set_snd_byte(self,b2):
        if b2.is_byte():
            newval = SU.compute_dw_value(self.byte1,b2.value,self.byte3,self.byte4)
            return SimDoubleWordValue(newval,self.undefined)
        raise SU.CHBSimOpError('set snd byte', [ self, b1 ])

    def add(self,other):
        newval = (self.value + other.value) % (SU.max32 + 1)
        return SimDoubleWordValue(newval,self.undefined or other.undefined)

    def add_overflows(self,other):
        return self.outside_signed_bounds(self.to_signed_int() + other.to_signed_int())

    def add_carries(self,other):
        return self.outside_unsigned_bounds(self.value + other.value)

    def sub(self,other):
        newval = (self.value - other.value) % (SU.max32 + 1)
        return SimDoubleWordValue(newval,self.undefined or other.undefined)

    def sub_overflows(self,other):
        return self.outside_signed_bounds(self.to_signed_int() - other.to_signed_int())

    def sub_carries(self,other):
        return self.outside_unsigned_bounds(self.value - other.value)

    def mul(self,other):
        newval = self.value * other.value
        return SimQuadWordValue(newval,self.undefined or other.undefined)

    def bitwise_and(self,other):
        newval = (self.value & other.value)
        return SimDoubleWordValue(newval,self.undefined or other.undefined)

    def bitwise_or(self,other):
        newval = (self.value | other.value)
        return SimDoubleWordValue(newval,self.undefined or other.undefined)

    def bitwise_not(self):
        newval = ~self.value
        return SimDoubleWordValue(newval,self.undefined)

    def bitwise_xor(self,other):
        newval = self.value ^ other.value
        return SimDoubleWordValue(newval,self.undefined or other.undefined)

    def bitwise_rol(self,other):
        otherval = other.value % 32        
        if otherval == 0: return self
        newval = (self.value << otherval) + (self.value >> (32-otherval))
        return SimDoubleWordValue(newval,self.undefined or other.undefined)

    def bitwise_ror(self,other):
        otherval = other.value % 32        
        if otherval == 0: return self
        newval = (self.value >> otherval) + (self.value << (32-otherval))
        return SimDoubleWordValue(newval,self.undefined or other.undefined)

    def bitwise_rcl(self,other,cflag):
        otherval = other.value & 31
        if otherval == 0: return (cflag,self)
        newval = self.value
        for cnt in range(0,otherval):
            tempcf = newval >> 31
            newval = (newval * 2) + cflag
            cflag = tempcf
        return (cflag,SimDoubleWordValue(newval,self.undefined or other.undefined))

    def bitwise_shrd(self,srcval,shift):
        shiftval = shift.value & 31
        if shiftval == 0: return (None,self)
        newval = self.value >> (shiftval - 1)
        cflag = newval % 2
        newval = newval >> 1
        srcinval = ((srcval.value << (32 - shiftval)) >> (32 - shiftval)) << (32 - shiftval)
        newval = newval + srcinval
        return (cflag,SimDoubleWordValue(newval,self.undefined or srcval.undefined or shift.undefined))

    def bitwise_shld(self,srcval,shift):
        shiftval = shift.value & 31
        if shiftval == 0: return (None,self)
        newval = self.value << (shiftval - 1)
        cflag = newval % 2
        newval = newval << 1
        srcinval = srcval.value >> (32 - shiftval)
        newval = newval + srcinval
        return (cflag,SimDoubleWordValue(newval,self.undefined or srcval.undefined or shift.undefined))

    def bitwise_shl(self,other):
        otherval = other.value & 31
        if otherval == 0: return (None,self)
        newval = self.value << (otherval - 1)
        msb = newval >> 31
        newval = newval << 1
        return (msb,SimDoubleWordValue(newval,self.undefined or other.undefined))

    def bitwise_shr(self,other):
        otherval = other.value & 31
        if otherval == 0: return (None,self)
        newval = self.value >> (otherval - 1)
        lsb = newval % 2
        newval = newval >> 1
        return (lsb,SimDoubleWordValue(newval,self.undefined or other.undefined))

    def bitwise_sar(self,other):
        otherval = other.value & 31
        if otherval == 0: return (None,self)
        newval = self.value >> (otherval - 1)
        lsb = newval % 2
        newval = newval >> 1
        if self.get_msb() > 0:
            c = ((1 << (otherval + 1)) - 1) << (32 - otherval)
            newval += c
        return (lsb,SimDoubleWordValue(newval,self.undefined or other.undefined))

    def get_lsb(self): return self.value % 2     # least significant bit

    def get_msb(self): return self.value >> 31   # most sigificant bit

    def get_msb2(self): return (self.value >> 30) % 4  #  2nd most significant bit

    def get_offset(self): return self.to_signed_int()

    def get_low_byte(self): return SimByteValue(self.byte1,not self.b1defined)

    def get_snd_byte(self): return SimByteValue(self.byte2,not self.b2defined)

    def get_third_byte(self): return SimByteValue(self.byte3,not self.b3defined)

    def get_high_byte(self): return SimByteValue(self.byte4,not self.b4defined)

    def get_low_word(self):
        return SimWordValue((self.byte2 << 8) + self.byte1,self.undefined)

    def get_low_half(self): return get_low_word()

    def get_high_half(self):
        return SimWordValue((self.byte4 << 8) + self.byte3,self.undefined)

    def to_doubleword(self,signextend=True): return self

    def sign_extend(self,size):
        if size == 4: return self
        raise CHBError('Cannot sign extend a doubleword value to ' + str(size))

    def to_double_size(self,dwhigh):
        newval = self.value + (dwhigh.value << 32)
        return SimQuadWordValue(newval,self.undefined or dwhigh.undefined)

    def to_unsigned_int(self): return self.value

    def to_signed_int(self):
        if self.is_negative():
            return self.value - (SU.max32 + 1)
        else:
            return self.value

    def __str__(self):
        if not self.symbolic is None:
            return self.symbolic
        if self.undefined:
            return '?'
        pb1 = 'b1:' + str(self.byte1) if self.b1defined else 'b1:?'
        pb2 = 'b2:' + str(self.byte2) if self.b2defined else 'b2:?'
        pb3 = 'b3:' + str(self.byte3) if self.b3defined else 'b3:?'
        pb4 = 'b4:' + str(self.byte4) if self.b4defined else 'b4:?'
        if not (self.b1defined and self.b2defined and self.b3defined and self.b4defined):            
            return '[' + pb1 + '; ' + pb2 + '; ' + pb3 + '; ' + pb4 + ']'
        else:
            return str(hex(self.value))

class SimQuadWordValue(SimValue):

    def __init__(self,value,undefined=False):
        SimValue.__init__(self,value & SU.max64,undefined)

    def get_low_half(self):
        return SimDoubleWordValue(self.value & SU.max32,self.undefined)

    def get_high_half(self):
        return SimDoubleWordValue(self.value >> 32,self.undefined)

    def __str__(self):
        if self.undefined: return '?'
        return str(hex(self.value))


def compose_simvalue(bytes):
    if len(bytes) == 1:
        return  bytes[0]
    elif len(bytes) == 2:
        b1 = bytes[0]
        b2 = bytes[1]
        if b1.undefined or b2.undefined:
            return SimWordValue(0,undefined=True)
        else:
            return SimWordValue(b2.value << 8 + b1.value)
    elif len(bytes) == 4:
        b1 = bytes[0]
        b2 = bytes[1]
        b3 = bytes[2]
        b4 = bytes[3]
        if b1.undefined or b2.undefined or b3.undefined or b4.undefined:
            return SimDoubleWordValue(0,undefined=True)
        else:
            bval = SU.compute_dw_value(b1.value,b2.value,b3.value,b4.value)
            return SimDoubleWordValue(bval)
    else:
        raise CHBError('Number of bytes not supported: ' + str(len(bytes)))

def mk_simvalue(size,value):
    if size == 1: return SimByteValue(value)
    elif size == 2: return SimWordValue(value)
    elif size == 4: return SimDoubleWordValue(value)
    else:
        raise CHBError('Size of value not supported: ' + str(size))

def mk_simhex_value(size,value): return mk_simvalue(size,int(value,16))

def mk_symbolic_simvalue(name):
    return SimDoubleWordValue(0,symbolic=name)
                                            
# constant SimValue's

simflagset = SimBoolValue(1)
simflagclr = SimBoolValue(0)
simflagundef = SimBoolValue(0,undefined=True)
simundefinedbyte = SimByteValue(0,undefined=True)
simundefined = SimDoubleWordValue(0,undefined=True)
simzerobyte = SimByteValue(0)
simzero = SimDoubleWordValue(0)
simone = SimDoubleWordValue(1)


if __name__ == '__main__':

    one = mk_simvalue(1,1)
    v = mk_simvalue(1,5)
    for i in range(0,10):
        v = v.bitwise_rol(one)
        print(str(i) + ': ' + str(v))
