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

from chb.models.DllSummary import DllSummary

class DllSummaryRef(DllSummary):

    def __init__(self,models,refnode,dll,name):
        self.models = models
        self.refnode = refnode
        self.chartype = self.refnode.get('char-type',None)
        self.typereplacements = {}
        self.name = name
        self.dll = dll
        self.refname = self.refnode.get('name')
        if 'lib' in self.refnode.attrib:
            self.refdll = self.refnode.get('lib')
            if self.refdll.endswith('_dll'):
                self.refdll = self.refdll[:-4] + '.dll'
            if not self.refdll.endswith('.dll') and not self.refdll.endswith('.drv'):
                self.refdll = self.refnode.get('lib') + '.dll'
        else:
            self.refdll = self.dll
            if not self.refdll.lower().endswith('.dll') and not self.refdll.endswith('.drv'):
                self.refdll = self.refdll + '.dll'
        self.xnode = self.models.stdpesummaries.get_summary_xnode(self.refdll,self.refname)
        if self.xnode is None:
            raise UF.CHBError('Problem with reference summary for ' +
                                 str(self.dll) + ', ' + str(self.name))

    def is_reference(self): return True
