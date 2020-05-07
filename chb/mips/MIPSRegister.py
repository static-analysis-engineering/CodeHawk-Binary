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

class MIPSRegisterBase(object):

    def __init__(self,bd,index,tags,args):
        self.bd = bd
        self.index = index
        self.tags = tags
        self.args = args

    def is_mips_register(self): return False
    def is_mips_stack_pointer(self): return False
    def is_mips_argument_register(self): return False
    def is_mips_special_register(self): return False
    def is_mips_floating_point_register(self): return False

    def get_key(self):
        return  (','.join(self.tags), ','.join([str(x) for x in self.args]))


# ------------------------------------------------------------------------------
# Regular MIPS Register
# ------------------------------------------------------------------------------

class MIPSRegister(MIPSRegisterBase):

    def __init__(self,bd,index,tags,args):
        MIPSRegisterBase.__init__(self,bd,index,tags,args)

    def is_mips_register(self): return True

    def is_mips_argument_register(self):
        return self.tags[1] in [ 'a0', 'a1', 'a2', 'a3' ]

    def is_mips_stack_pointer(self):
        return self.tags[1] in [ 'sp' ]

    def get_argument_index(self):
        if self.is_mips_argument_register():
            return int(self.tags[1][1:]) + 1

    def __str__(self): return self.tags[1]

# ------------------------------------------------------------------------------
# Regular MIPS Special Register
# ------------------------------------------------------------------------------

class MIPSSpecialRegister(MIPSRegisterBase):

    def __init__(self,bd,index,tags,args):
        MIPSRegisterBase.__init__(self,bd,index,tags,args)

    def is_mips_special_register(self): return True

    def __str__(self): return self.tags[1]

# ------------------------------------------------------------------------------
# Regular MIPS Floating Point Register
# ------------------------------------------------------------------------------

class MIPSFloatingPointRegister(MIPSRegisterBase):

    def __init__(self,bd,index,tags,args):
        MIPSRegisterBase.__init__(self,bd,index,tags,args)

    def is_mips_floating_point_register(self): return True

    def get_register_index(self): return int(self.args[0])

    def __str__(self): return '$f' + str(self.get_register_index()) 
