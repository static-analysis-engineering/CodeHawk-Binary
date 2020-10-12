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

import chb.util.IndexedTable as IT

class FunctionData(object):

    """
    rep-record representation
    id: function address (decimal)
    tags: (all optional)
          'l': library stub
          'nr': non-returning
          'nc': not-complete
          'ida': provided by IDA Pro
          'pre': obtained by preamble
          'u': user-provided
          'v': virtual
          'c': member of a c++ class
    args: if 'c' in tags:
            0: classname
            1: isstatic member
            2+: names   (string-index)
          else:
            0+: names   (string-index)
    """

    def __init__(self,fsdata,xnode):
        self.functionsdata = fsdata        #  FunctionsData
        self.xnode = xnode
        rep = IT.get_rep(xnode,indextag='id')
        self.id = rep[0]
        self.tags = rep[1]
        self.args = rep[2]
        self.faddr = str(hex(int(self.id)))

    def is_class_member(self): return 'c' in self.tags

    def is_by_preamble(self): return 'pre' in self.tags

    def is_library_stub(self): return 'l' in self.tags

    def has_name(self): return len(self.get_names()) > 0

    def get_name(self):
        if len(self.get_names()) > 0:
            return self.get_names()[0]
        else:
            return faddr

    def get_names(self):
        if self.is_class_member():
            return [ self.functionsdata.bdictionary.get_string(i) for i in self.args[2:] ]
        else:
            return [ self.functionsdata.bdictionary.get_string(i) for i in self.args ]

    def __str__(self):
        names = self.get_names()
        pnames = ""
        if len(names) > 0:
            pnames = ' (' + ','.join(self.get_names()) + ')'
        return self.faddr + pnames
        


class FunctionsData(object):

    def __init__(self,app,xnode):
        self.app = app     # AppAccess
        self.bdictionary = self.app.bdictionary
        self.xnode = xnode
        self.functions = {}      # hex-address -> FunctionData
        self._initialize()

    def has_function(self,faddr): return faddr in self.functions

    def has_name(self,faddr):
        if faddr in self.functions:
            return self.functions[faddr].has_name()
        else:
            return False

    def get_name(self,faddr):
        if self.has_name(faddr):
            return self.functions[faddr].get_names()[0]

    def get_names(self,faddr):
        if self.has_name(faddr):
            return self.functions[faddr].get_names()
        else:
            return []

    def get_library_stubs(self):   #  hexaddr -> name
        result = {}
        for f in self.functions.values():
            if f.is_library_stub():
                result[f.faddr] = f.get_name()
        return result

    def __str__(self):
        lines = []
        for fd in sorted(self.functions): lines.append(str(self.functions[fd]))
        return '\n'.join(lines)

    def _initialize(self):
        for x in self.xnode.findall('n'):
            fd = FunctionData(self,x)
            self.functions[fd.faddr] = fd

            
