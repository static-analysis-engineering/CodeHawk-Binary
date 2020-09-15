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

class MIPSOperandKindBase(D.DictionaryRecord):

    def __init__(self,d,index,tags,args):
        D.DictionaryRecord.__init__(self,d,index,tags,args)
        self.bd = self.d.app.bdictionary

    def is_mips_absolute(self): return False
    def is_mips_immediate(self): return False
    def is_mips_indirect_register(self): return False
    def is_mips_register(self): return False
    def is_mips_special_register(self): return False

    def to_expr_string(self): return self.__str__()

    def __str__(self): return 'operandkind:' + self.tags[0]

class MIPSRegisterOp(MIPSOperandKindBase):

    def __init__(self,d,index,tags,args):
        MIPSOperandKindBase.__init__(self,d,index,tags,args)

    def is_mips_register(self): return True

    def get_size(self): return 4

    def get_mips_register(self): return self.tags[1]

    def __str__(self): return str(self.get_mips_register())

class MIPSSpecialRegisterOp(MIPSOperandKindBase):

    def __init__(self,d,index,tags,args):
        MIPSOperandKindBase.__init__(self,d,index,tags,args)

    def is_mips_special_register(self): return True

    def get_mips_register(self): return self.tags[1]

    def __str__(self): return str(self.get_mips_register())


class MIPSIndirectRegisterOp(MIPSOperandKindBase):

    def __init__(self,d,index,tags,args):
        MIPSOperandKindBase.__init__(self,d,index,tags,args)

    def is_mips_indirect_register(self): return True

    def get_mips_register(self): return self.tags[1]

    def get_offset(self): return int(self.tags[2])

    def get_size(self): return 4

    def to_expr_string(self):
        if self.get_offset() == 0:
            return '*(' + str(self.get_mips_register() + ')' )
        else:
            return '*(' + str(self.get_mips_register() + ' + ' + str(self.get_offset()) + ')')

    def __str__(self):
        return str(self.get_offset()) + '(' + str(self.get_mips_register()) + ')'

class MIPSImmediateOp(MIPSOperandKindBase):

    def __init__(self,d,index,tags,args):
        MIPSOperandKindBase.__init__(self,d,index,tags,args)

    def is_mips_immediate(self): return True

    def get_value(self): return int(self.tags[1])

    def to_unsigned_int(self): return self.get_value()

    def to_signed_int(self): return self.get_value()

    def __str__(self): return str(hex(self.get_value()))

class MIPSAbsoluteOp(MIPSOperandKindBase):

    def __init__(self,d,index,tags,args):
        MIPSOperandKindBase.__init__(self,d,index,tags,args)

    def get_address(self): return self.bd.get_address(self.args[0])

    def is_mips_absolute(self): return True

    def __str__(self): return str(self.get_address())

class MIPSFloatingPointRegisterOp(MIPSOperandKindBase):

    def __innit__(self,d,index,tags,args):
        MIPSOperandKindBase.__init__(self,d,index,tags,args)

    def get_register_index(self): return int(self.args[0])

    def is_mips_floating_point_register(self): return True

    def __str__(self): return 'FP(' + str(self.get_register_index()) + ')'
