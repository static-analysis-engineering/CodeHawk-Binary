# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2017-2020 Kestrel Technology LLC
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

import xml.etree.ElementTree as ET

import chb.util.IndexedTable as IT

def has_control_characters(s):
    for c in s:
        if ord(c) < 32 or ord(c) > 126:
            return True

    else:
        return False

def byte_to_string(b): return '{:02x}'.format(b)

def value_from_hex(s): return int(s,16)

def hexstring(s):
    result = ''
    for c in s:
        result += byte_to_string(ord(c))
    return result

def dehexstring(h):
    h = h[:]
    result = ''
    try:
        for i in range(len(h)/2):
            result += chr(int(h[:2],16))
            h = h[2:]
        return result
    except:
        print('Error in dehexing string: ' + h)
        exit(1)

def decode(ishex,h):
    if ishex:
        return dehexstring(h)
    else:
        return h

def encode(s):
    if has_control_characters(s):
        return (True,hexstring(s))
    else:
        return (False,s)


class StringIndexedTable(object):

    def __init__(self,name):
        self.name = name
        self.stringtable= {}      # string -> index
        self.indextable = {}      # index -> string
        self.next = 1

    def reset(self):
        self.stringtable = {}
        self.indextable = {}
        self.next = 1

    def add(self,s):
        if s is None:
            raise  IT.IndexedTableError(self.name + ': Attempt to index None')
        if s in self.stringtable:
            return self.stringtable[s]
        else:
            index = self.next
            self.stringtable[s] = index
            self.indextable[index] = s
            self.next += 1
            return index

    def size(self): return (self.next - 1)

    def values(self): return sorted(self.stringtable.keys())

    def retrieve(self,index):
        if index in self.indextable:
            return self.indextable[index]
        else:
            msg = ('Unable to retrieve item ' + str(index) + ' from table ' + self.name
                      + ' (size: ' + str(self.size()) + ')')
            raise IT.IndexedTableError(msg + '\n' + self.name + ', size: ' + str(self.size()))

    def read_xml(self,node):
        if node is None:
            print('Xml node not present in string table')
            raise IT.IndexedTableError('Xml node not present in string table')
        for snode in node.findall('n'):
            index = int(snode.get('ix'))
            ishex = snode.get('hex','no') == 'yes'
            s = decode(ishex,snode.get('v'))
            self.stringtable[s] = index
            self.indextable[index] = s
            if index >= self.next:
                self.next = index + 1

    def write_xml(self,node):
        for index in sorted(self.indextable):
            s = self.indextable[index]
            (ishex,sencoded) = encode(s)
            snode = ET.Element('n')
            snode.set('v',sencoded)
            snode.set('ix',str(index))
            node.append(snode)

    def __str__(self):
        lines = []
        lines.append('\nstring-table')
        for ix in sorted(self.indextable):
            lines.append(str(ix).rjust(4) + ' ' + str(self.indextable[ix]))
        return '\n'.join(lines)




if __name__ == '__main__':

    print(str(has_control_characters('\n')))
    print(str(has_control_characters('string')))

    print(hexstring('\n\n'))
    print(dehexstring('0a0a'))

    print(decode(*encode('string')))
    print(decode(*encode('\n\n')))

    print(dehexstring('4d4158504154484c454e3d25640a'))
    print(dehexstring('496e7075742070617468203d2025732c207374726c656e287061746829203d2025640a'))
    print(dehexstring('4d4158504154484c454e203d2025640a'))


