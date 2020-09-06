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



class FunctionInfo(object):

    def __init__(self,app,xnode):
        self.app = app                  # AppAccess
        self.ixd = self.app.interfacedictionary   # InterfaceDictionary
        self.xnode = xnode
        self.calltargets = {}           # faddr -> CallTarget
        self.variablenames = {}         # variable seq number -> name
        self._initialize_call_targets()

    def get_call_target(self,faddr):
        if self.has_call_target(faddr):
            return self.calltargets[faddr]

    def has_call_target(self,faddr):
        return faddr in self.calltargets

    def has_variable_name(self,index): return index in self.variablenames

    def get_variable_name(self,index):
        if index in self.variablenames: return self.variablenames[index]

    def _initialize_call_targets(self):
        ctnode = self.xnode.find('call-targets')
        for x in ctnode.findall('ctinfo'):
            self.calltargets[ x.get('a') ] = self.ixd.read_xml_call_target(x)
        vnnode = self.xnode.find('variable-names')
        if not vnnode is None:
            for x in  vnnode.findall('n'):
                self.variablenames[ int(x.get('vix')) ] = x.get('name')
