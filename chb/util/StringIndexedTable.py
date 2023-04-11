# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2017-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021-2023 Aarno Labs LLC
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

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT

from typing import Dict, List, Optional, Tuple


def has_control_characters(s: str) -> bool:
    for c in s:
        if ord(c) < 32 or ord(c) > 126:
            return True
    else:
        return False


def byte_to_string(b: int) -> str:
    return '{:02x}'.format(b)


def value_from_hex(s: str) -> int:
    return int(s, 16)


def hexstring(s: str) -> str:
    result = ''
    for c in s:
        result += byte_to_string(ord(c))
    return result


def dehexstring(h: str) -> str:
    h = h[:]
    result = ''
    try:
        for i in range(len(h) // 2):
            result += chr(int(h[:2], 16))
            h = h[2:]
        return result
    except Exception:
        print('Error in dehexing string: ' + h)
        exit(1)


def decode(ishex: bool, h: str) -> str:
    if ishex:
        return dehexstring(h)
    else:
        return h


def encode(s: str) -> Tuple[bool, str]:
    if has_control_characters(s):
        return (True, hexstring(s))
    else:
        return (False, s)


class StringIndexedTable:

    def __init__(self, name: str) -> None:
        self.name = name
        self.stringtable: Dict[str, int] = {}      # string -> index
        self.indextable: Dict[int, str] = {}      # index -> string
        self.next = 1

    def reset(self) -> None:
        self.stringtable = {}
        self.indextable = {}
        self.next = 1

    def add(self, s: str) -> int:
        if s is None:
            raise IT.IndexedTableError(self.name + ': Attempt to index None')
        if s in self.stringtable:
            return self.stringtable[s]
        else:
            index = self.next
            self.stringtable[s] = index
            self.indextable[index] = s
            self.next += 1
            return index

    def size(self) -> int:
        return (self.next - 1)

    def values(self) -> List[str]:
        return sorted(self.stringtable.keys())

    def retrieve(self, index: int) -> str:
        if index in self.indextable:
            return self.indextable[index]
        else:
            msg = (
                'Unable to retrieve item '
                + str(index)
                + ' from table '
                + self.name
                + ' (size: '
                + str(self.size())
                + ')')
            raise IT.IndexedTableError(
                msg
                + '\n'
                + self.name
                + ', size: '
                + str(self.size()))

    def read_xml(self, node: Optional[ET.Element]) -> None:
        if node is None:
            print('Xml node not present in string table')
            raise IT.IndexedTableError('Xml node not present in string table')
        for snode in node.findall('n'):
            ix = snode.get("ix")
            if ix is None:
                raise UF.CHBError("StringIndexTable: index is missing")
            index = int(ix)
            ishex = snode.get('hex', 'no') == 'y'
            v = snode.get("v")
            if v is None:
                raise UF.CHBError(
                    "StringIndexTable: value is missing for index " + str(index))
            s = decode(ishex, v)
            self.stringtable[s] = index
            self.indextable[index] = s
            if index >= self.next:
                self.next = index + 1

    def write_xml(self, node: ET.Element) -> None:
        for index in sorted(self.indextable):
            s = self.indextable[index]
            (ishex, sencoded) = encode(s)
            snode = ET.Element('n')
            snode.set('v', sencoded)
            snode.set('ix', str(index))
            node.append(snode)

    def __str__(self) -> str:
        lines: List[str] = []
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
    print(dehexstring(
        '496e7075742070617468203d2025732c207374726c656e287061746829203d2025640a'))
    print(dehexstring('4d4158504154484c454e203d2025640a'))
