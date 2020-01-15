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

import chb.app.DictionaryRecord as D

class OperandKindBase(D.DictionaryRecord):

    def __init__(self,d,index,tags,args):
        D.DictionaryRecord.__init__(self,d,index,tags,args)
        self.bd = self.d.app.bdictionary

    def is_flag(self): return False
    def is_register(self): return False
    def is_immediate(self): return False
    def is_absolute(self): return False
    def is_indirect_register(self): return False
    def is_scaled_indirect_register(self): return False
    def is_double_register(self): return False

    def to_operand_string(self): return self.__str__()
    def to_address_string(self): return 'address-string?'

    def __str__(self): return 'operandkind:' + self.tags[0]


class FlagOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def is_flag(self): return True

    def get_flag(self): return self.tags[1]

    def __str__(self): return str(self.get_flag())


class RegisterOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def is_register(self): return True

    def get_register(self): return self.tags[1]

    def __str__(self): return str(self.get_register())

class FpuRegisterOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def get_register(self): return self.args[0]

    def __str__(self): return '%st(' + str(self.get_register()) + ')'

class ControlRegisterOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def get_register(self): return self.args[0]

    def __str__(self): return 'CR' + str(self.get_register())

class DebugRegisterOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def get_register(self): return self.args[0]

    def __str__(self): return 'DR' + str(self.get_register())

class MmRegisterOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def get_register(self): return self.args[0]

    def __str__(self): return '%mm' + str(self.get_register())

class XmmRegisterOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def get_register(self): return self.args[0]

    def __str__(self): return '%xmm' + str(self.get_register())

class SegRegisterOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def get_register(self): return self.tags[1]

    def __str__(self): return str(self.get_register())

class IndirectRegisterOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def is_indirect_register(self): return True

    def get_register(self): return self.tags[1]

    def get_offset(self): return int(self.tags[2])

    def to_operand_string(self):
        offset = self.get_offset()
        if offset == 0:
            index = str(self.get_register())
        elif offset > 0:
            index = str(self.get_register() + '+' + str(offset))
        else:
            index = str(self.get_register() + '-' + str(abs(offset)))
        return 'mem[' + index + ']'

    def to_address_string(self):
        offset = self.get_offset()
        if offset == 0: return str(self.get_register())
        elif offset > 0: return str(self.get_register()) + '+' + str(offset)
        else: return str(self.get_register()) + '-' + str(abs(offset))

    def __str__(self):
        return str(self.get_offset()) + '(' + str(self.get_register()) + ')'

class SegIndirectRegisterOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

class  ScaledIndirectRegisterOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def is_scaled_indirect_register(self): return True

    def get_base_register(self):
        return None if self.tags[1] == 'none' else self.tags[1]

    def get_ind_register(self):
        return None if self.tags[2] == 'none' else self.tags[2]

    def get_scale(self): return int(self.args[0])

    def get_offset(self): return int(self.tags[3])

    def __str__(self):
        r1 = '' if self.get_base_register() is None else self.get_base_register()
        r2 = '' if self.get_ind_register() is None else self.get_ind_register()
        return (str(self.get_offset()) + '(' + r1 + ',' + r2 + ','
            + str(self.get_scale()) + ')')

class DoubleRegisterOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def is_double_register(self): return True

    def get_reg_high(self): return self.tags[1]

    def get_reg_low(self): return self.tags[2]

    def __str__(self): return self.get_reg_high() + ':' + self.get_reg_low()


class ImmediateOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def is_immediate(self): return True

    def get_value(self): return int(self.tags[1])

    def __str__(self): return str(hex(self.get_value()))

class AbsoluteOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def get_address(self): return self.bd.get_address(self.args[0])

    def is_absolute(self): return True

    def __str__(self): return str(self.get_address())
    
class SegAbsoluteOp(OperandKindBase):

    def __init__(self,d,index,tags,args):
        OperandKindBase.__init__(self,d,index,tags,args)

    def get_segment(self): return self.tags[0]

    def get_address(self): return self.bd.get_address(self.args[0])

    def __str__(self): return self.get_segment() + ':' + str(self.get_address())
