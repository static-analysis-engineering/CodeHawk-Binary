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

class PESection():
    """Provides access to the raw data in a PE section."""

    def __init__(self,ipeheader,xnode):
        self.ipeheader = ipeheader
        self.xnode = xnode

    def get_size(self): return self.xnode.get('size')

    def get_virtual_address(self): return self.xnode.get('va')

    def get_block_count(self): return self.xnode.find('hex-data').get('blocks')

    def get_strings(self,minlen=3):
        '''Yield sequences of printable characters of mimimum length minlen'''
        def makestream(s):
            c = 0
            for w in s.split():
                for i in range(0,len(w),2):
                    yield((c*8) + i,int(w[i:i+2],16))
                c += 1
        def is_printable(i): return (i >= 32 and i < 127)
        result = []
        for b in self.xnode.find('hex-data').findall('ablock'):
            for a in b.findall('aline'):
                va = int(a.get('va'),16)
                for (offset,i) in makestream(a.get('bytes')):
                    if is_printable(i):
                        result.append(i)
                    else:
                        if len(result) >= minlen:
                            strva = (va + (offset/2)) - len(result)
                            strval = result[:]
                            result = []
                            yield (strva,strval)
                        else:
                            result = []

    def get_zero_blocks(self,va,align=32):
        s = ''
        offsetalign = 2*align
        z = '0' * offsetalign
        qalign =  int(align/4)
        qoffsetalign = int(offsetalign/4)
        qz = '0' * qoffsetalign
        for b in self.xnode.find('hex-data').findall('ablock'):
            for a in b.findall('aline'):
                s += a.get('bytes').replace(' ','')
        va = int(va,16)
        offset = 0
        slen = len(s)
        result = []
        while (va % align) > 0:
            va += 1
            offset += 2
        while offset < slen - offsetalign:
            while s[offset:offset+offsetalign] != z:
                va += align
                offset += offsetalign
                if offset > slen - offsetalign: break
            if offset > slen - qoffsetalign: break
            dbstart = hex(va)
            while (s[offset:offset+qoffsetalign] == qz):
                va += qalign
                offset += qoffsetalign
                if offset > slen - qoffsetalign: break
            dbend = hex(va)
            result.append((dbstart,dbend))
        return result


    def __str__(self):
        lines = []
        lines.append('-' * 80)
        lines.append('Section at ' + self.get_virtual_address() +
                     ' (size: ' + self.get_size() + ')')
        lines.append('-' * 80)
        for b in self.xnode.find('hex-data').findall('ablock'):
            for line in b.findall('aline'):
                lines.append(line.get('va') + '    ' + line.get('bytes').ljust(40) +
                             line.get('print'))
        lines.append('=' * 80)
        return '\n'.join(lines)
        
