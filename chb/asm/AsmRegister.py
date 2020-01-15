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
"""X86 CPU Register data."""

class AsmRegisterBase(object):

    def __init__(self,bd,index,tags,args):
        self.bd = bd
        self.index = index
        self.tags = tags
        self.args = args

    def is_cpu_register(self): return False
    def is_segment_register(self): return False
    def is_double_register(self): return False
    def is_floating_point_register(self): return False
    def is_control_register(self): return False
    def is_debug_register(self): return False
    def is_mmx_register(self): return False
    def is_xmm_register(self): return False

    def get_key(self):
        return  (','.join(self.tags), ','.join([str(x) for x in self.args]))

# ------------------------------------------------------------------------------
# CPURegister
# ------------------------------------------------------------------------------

class CPURegister(AsmRegisterBase):

    def __init__(self,bd,index,tags,args):
        AsmRegisterBase.__init__(self,bd,index,tags,args)

    def is_cpu_register(self): return True

    def __str__(self): return self.tags[1]

# ------------------------------------------------------------------------------
# SegmentRegister
# ------------------------------------------------------------------------------

class SegmentRegister(AsmRegisterBase):

    def __init__(self,bd,index,tags,args):
        AsmRegisterBase.__init__(self,bd,index,tags,args)

    def is_segment_register(self): return True

    def  __str__(self): return self.tags[1]

# ------------------------------------------------------------------------------
# DoubleRegister
# ------------------------------------------------------------------------------
       
class DoubleRegister(AsmRegisterBase):

    def __init__(self,bd,index,tags,args):
        AsmRegisterBase.__init__(self,bd,index,tags,args)

    def is_double_register(self): return True

    def __str__(self): return self.tags[1] + ':' + self.tags[2]


# ------------------------------------------------------------------------------
# FloatingPointRegister
# ------------------------------------------------------------------------------

class FloatingPointRegister(AsmRegisterBase):

    def __init__(self,bd,index,tags,args):
        AsmRegisterBase.__init__(self,bd,index,tags,args)

    def is_floating_point_register(self): return True

    def get_index(self): return self.args[0]

    def __str__(self): return 'st(' + str(self.get_index()) + ')'
    
# ------------------------------------------------------------------------------
# ControlRegister
# ------------------------------------------------------------------------------

class ControlRegister(AsmRegisterBase):

    def __init__(self,bd,index,tags,args):
        AsmRegisterBase.__init__(self,bd,index,tags,args)

    def is_control_register(self): return True

    def get_index(self): return self.args[0]

    def __str__(self): return 'CR' + str(self.get_index())

# ------------------------------------------------------------------------------
# DebugRegister
# ------------------------------------------------------------------------------

class DebugRegister(AsmRegisterBase):

    def __init__(self,bd,index,tags,args):
        AsmRegisterBase.__init__(self,bd,index,tags,args)

    def is_debug_register(self): return True

    def get_index(self): return self.args[0]

    def __str__(self): return 'DR' + str(self.get_index())

# ------------------------------------------------------------------------------
# MmxRegister
# ------------------------------------------------------------------------------

class MmxRegister(AsmRegisterBase):

    def __init__(self,bd,index,tags,args):
        AsmRegisterBase.__init__(self,bd,index,tags,args)

    def is_mmx_register(self): return True

    def get_index(self): return self.args[0]

    def __str__(self): return 'mm(' + str(self.get_index()) + ')'

# ------------------------------------------------------------------------------
# XmmRegister
# ------------------------------------------------------------------------------

class XmmRegister(AsmRegisterBase):

    def __init__(self,bd,index,tags,args):
        AsmRegisterBase.__init__(self,bd,index,tags,args)

    def is_xmm_register(self): return True

    def get_index(self): return self.args[0]

    def __str__(self): return 'xmm(' + str(self.get_index()) + ')'
