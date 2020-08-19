# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2017-2020 Kestrel Technology LLC
# Copyright (c)           Henny Sipma
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

class IndexedTableError(UF.CHBError):

    def __init__(self,msg,items=[]):
        self.msg = msg
        self.items = items

    def __str__(self):
        lines = []
        if len(self.items) > 0 and len(self.items) < 20:
            lines.append('-')
            for (index,i) in self.items:
                lines.append(str(index).rjust(3) + ': ' + str(i))
            lines.append('-')
        lines.append(self.msg)
        return '\n'.join(lines)

def get_rep(node,indextag='ix'):
    tags = node.get('t')
    args = node.get('a')
    try:
        if tags is None:
            taglist = []
        else:
            taglist = tags.split(',')
        if args is None or args == '':
            arglist = []
        else:
            arglist = [ int(x) for x in args.split(',') ]
        index = int(node.get(indextag))
        return (index,taglist,arglist)
    except Exception as e:
        print('tags: ' + str(tags))
        print('args: ' + str(args))
        print(e)
        raise

def get_key(tags,args): return (','.join(tags), ','.join([str(x) for x in args]))

class IndexedTable (object):
    """Table that provides unique indices to objects represented by a key string.

    The table can be checkpointed and reset to that checkpoint with
    - set_checkpoint
    - reset_to_checkpoint

    Note: the string encodings use the comma as a concatenation character, hence
          the comma character cannot be used in any string representation.
    """

    def __init__(self,name):
        self.name = name
        self.keytable = {}              # key -> index
        self.indextable = {}            # index -> object
        self.next = 1
        self.reserved = []
        self.checkpoint = None

    def reset(self):
        self.keytable = {}
        self.indextable = {}
        self.next = 1
        self.reserved = []
        self.checkpoint = None

    def set_checkpoint(self):
        if self.checkpoint is None:
            self.checkpoint = self.next
            return self.next
        raise IndexedTableError("Checkpoint has already been set at "
                                       + str(self.checkpoint))

    def iter(self,f):
        for (i,v) in self.items(): f(i,v)

    def reset_to_checkpoint(self):
        '''Remove all entries added since the checkpoint was set.'''
        cp = self.checkpoint
        if cp is None:
            raise InvalidArgumentError("Cannot reset non-existent checkpoint")
        for i in range(cp,self.next):
            if i in self.reserved:
                continue
            self.indextable.pop(i)
        for k in self.keytable.keys():
            if self.keytable[k] >= cp:
                self.keytable.pop(k)
        self.checkpoint = None
        self.reserved = []
        self.next = cp
        return cp

    def remove_checkpoint(self): self.checkpoint = None        

    def add(self,key,f):
        if key in self.keytable:
            return self.keytable[key]
        else:
            index = self.next
            obj = f(index, key)
            self.keytable[key] = index
            self.indextable[index] = obj
            self.next += 1
            return index

    def reserve(self):
        index = self.next
        self.reserved.append(index)
        self.next += 1
        return index

    def values(self):
        result = []
        for i in sorted(self.indextable):
            result.append(self.indextable[i])
        return result

    def items(self):
        result = []
        for i in sorted(self.indextable):
            result.append((i,self.indextable[i]))
        return result

    def commit_reserved(self,index,key,obj):
        if index in self.reserved:
            self.keytable[key] = index
            self.indextable[index] = obj
            self.reserved.remove(index)
        else:
            raise IndexedTableError("Trying to commit nonexisting index: " + str(index))

    def size(self): return (self.next - 1)

    def retrieve(self,index):
        if index in self.indextable:
            return self.indextable[index]
        else:
            msg = ('Unable to retrieve item ' + str(index) + ' from table ' + self.name
                      + ' (size: ' + str(self.size()) + ')')
            items = self.items()
            raise IndexedTableError(msg + '\n' + self.name + ', size: ' + str(self.size()),items=items)

    def retrieve_by_key(self,f):
        result = []
        for key in self.keytable:
            if f(key):
                result.append((key,self.indextable[self.keytable[key]]))
        return result

    def write_xml(self,node,f,tag='n'):
        for key in sorted(self.indextable):
            snode = ET.Element(tag)
            f(snode,self.indextable[key])
            node.append(snode)

    def read_xml(self,node,tag,get_value,
                     get_key=lambda x:x.get_key(),
                     get_index=lambda x:x.index):
        if node is None:
            print('Xml node not present in ' + self.name)
            raise IndexedTableError(self.name)
        for snode in node.findall(tag):
            obj = get_value(snode)
            key = get_key(obj)
            index = get_index(obj)
            self.keytable[key] = index
            self.indextable[index] = obj
            if index >= self.next:
                self.next = index + 1

    def __str__(self):
        lines = []
        lines.append('\n' + self.name)
        for ix in sorted(self.indextable):
            lines.append(str(ix).rjust(4) + '  ' + str(self.indextable[ix]))
        if len(self.reserved) > 0:
            lines.append('Reserved: ' + str(self.reserved))
        if not self.checkpoint is None:
            lines.append('Checkpoint: ' + str(self.checkpoint))
        return '\n'.join(lines)
            
if __name__ == '__main__':

    table = IndexedTable('test')
    print('Size: ' + str(table.size()))

    try:
        table.retrieve(1)
    except UF.CHBError as e:
        print(str(e.wrap()))
