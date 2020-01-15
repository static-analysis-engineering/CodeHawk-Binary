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

class StringXRefs(object):

    def __init__(self,stringsxrefs,xnode):
        self.stringsxrefs = stringsxrefs
        self.xnode = xnode
        self.strval = self.stringsxrefs.bdictionary.read_xml_string(self.xnode)
        self.addr = self.xnode.get('a')
        self.xrefs = []     # (faddr,iaddr) list
        self._initialize()

    def _initialize(self):
        for x in self.xnode.findall('xref'):
            self.xrefs.append((x.get('f'),x.get('ci')))


class StringsXRefs(object):

    def __init__(self,app,xnode):
        self.app = app   # AppAccess
        self.bdictionary = self.app.bdictionary
        self.xnode = xnode
        self.strings = {}  # hex-address -> StringXRefs
        self._initialize()

    def iter_strings(self,f):
        for a in sorted(self.strings): f(a,self.strings[a])

    def has_string(self,addr): return addr in self.strings

    def get_string(self,addr):
        if self.has_string(addr):
            return self.strings[addr].strval

    def get_xrefs(self):
        result = []
        for sxref in self.strings: result.extend(self.strings[sxref].xrefs)
        return result

    def get_function_xref_strings(self):    #  returns faddr -> strval -> count
        result = {}
        for sxref in self.strings:
            xref = self.strings[sxref]
            strval = xref.strval
            for (faddr,iaddr) in xref.xrefs:
                result.setdefault(faddr,{})
                result[faddr].setdefault(strval,0)
                result[faddr][strval] += 1
        return result

    def _initialize(self):
        for x in self.xnode.findall('string-xref'):
            xrefs = StringXRefs(self,x)
            self.strings[xrefs.addr] = xrefs
        
