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

from chb.models.DllFunctionParameter import DllFunctionParameter

class DllFunctionAPI(object):

    def __init__(self,summary,xnode):
        self.summary = summary
        self.xnode = xnode
        
    def get_calling_convention(self): return xnode.get('cc')

    def get_adjustment(self): return int(xnode.get('adj'))

    def get_parameters(self):
        return [ DllFunctionParameter(self,p) for p in self.xnode.findall('par') ]

    def get_stack_parameters(self):
        stackparams = [ p for p in self.get_parameters() if p.is_stack_parameter() ]
        return sorted(stackparams,key=lambda p:p.get_stack_nr())
        
    def get_stack_parameter_names(self):
        stackparams = self.get_stack_parameters()
        return [ p.name for p in stackparams ]
