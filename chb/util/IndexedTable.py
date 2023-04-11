# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
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

from typing import Any, Callable, Dict, Generic, List, Optional, Tuple, TypeVar


class IndexedTableError(UF.CHBError):

    def __init__(
            self,
            msg: str,
            itemlist: List[Tuple[int, "IndexedTableValue"]] = []) -> None:
        UF.CHBError.__init__(self, msg)
        self._itemlist = itemlist

    @property
    def itemlist(self) -> List[Tuple[int, "IndexedTableValue"]]:
        return self._itemlist

    def __str__(self) -> str:
        lines: List[str] = []
        if len(self.itemlist) > 0 and len(self.itemlist) < 20:
            lines.append('-')
            for (index, i) in self.itemlist:
                lines.append(str(index).rjust(3) + ': ' + str(i))
            lines.append('-')
        lines.append(self.msg)
        return '\n'.join(lines)


class IndexedTableValueMismatchError(UF.CHBError):

    def __init__(
            self,
            tag: str,
            reqtagcount: int,
            reqargcount: int,
            acttagcount: int,
            actargcount: int,
            name: str) -> None:
        UF.CHBError.__init__(
            self,
            "Dictionary record mismatch for "
            + tag
            + " in "
            + name
            + ": Expected "
            + str(reqtagcount)
            + " tags and "
            + str(reqargcount)
            + " args, but found "
            + str(acttagcount)
            + " tags and "
            + str(actargcount))


def get_rep(
        node: ET.Element,
        indextag: str = "ix") -> Tuple[int, List[str], List[int]]:
    tags: Optional[str] = node.get('t')
    args: Optional[str] = node.get('a')
    try:
        if tags is None:
            taglist: List[str] = []
        else:
            taglist = tags.split(",")
        if args is None or args == "":
            arglist: List[int] = []
        else:
            arglist = [int(x) for x in args.split(",")]
        nodeindex: Optional[str] = node.get(indextag)
        if nodeindex is None:
            raise UF.CHBError("Error in indextable representation: "
                              + " index tag is missing")
        index = int(nodeindex)
        return (index, taglist, arglist)
    except Exception as e:
        print("tags: " + str(tags))
        print("args: " + str(args))
        print(str(e))
        raise


def get_key(tags: List[str], args: List[int]) -> Tuple[str, str]:
    return (",".join(tags), ",".join([str(x) for x in args]))


class IndexedTableValue:

    def __init__(
            self,
            index: int,
            tags: List[str],
            args: List[int]) -> None:
        self._index = index
        self._tags = tags
        self._args = args

    @property
    def index(self) -> int:
        return self._index

    @property
    def tags(self) -> List[str]:
        return self._tags

    @property
    def args(self) -> List[int]:
        return self._args

    @property
    def key(self) -> Tuple[str, str]:
        return (",".join(self.tags), ",".join([str(x) for x in self.args]))

    def check_key(self, reqtagcount: int, reqargcount: int, name: str) -> None:
        """Check if the constructed value has the expected tags and args."""
        acttagcount = len(self.tags)
        actargcount = len(self.args)
        if acttagcount == reqtagcount and actargcount == reqargcount:
            return
        raise IndexedTableValueMismatchError(
            self.tags[0], reqtagcount, reqargcount, acttagcount, actargcount, name)

    def write_xml(self, node: ET.Element) -> None:
        (tagstr, argstr) = self.key
        if len(tagstr) > 0:
            node.set("t", tagstr)
        if len(argstr) > 0:
            node.set("a", argstr)
        node.set("ix", str(self.index))

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("\nIndex table value\n--------------------------")
        lines.append("index: " + str(self.index))
        lines.append("tags : [" + ", ".join(self.tags) + "]")
        lines.append("args : [" + ", ".join(str(x) for x in self.args) + "]")
        lines.append("")
        return "\n".join(lines)


def get_value(node: ET.Element) -> IndexedTableValue:
    rep = get_rep(node)
    return IndexedTableValue(*rep)


class IndexedTableSuperclass:

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def size(self) -> int:
        raise UF.CHBError("Size not overridden in IndexedTableSuperclass")

    def reset(self) -> None:
        raise UF.CHBError("Reset not overridden in IndexedTableSuperclass")


V = TypeVar("V", bound=IndexedTableValue)


class IndexedTable(IndexedTableSuperclass):
    """Table that provides unique indices to objects represented by a key string.

    The table can be checkpointed and reset to that checkpoint with
    - set_checkpoint
    - reset_to_checkpoint

    Note: the string encodings use the comma as a concatenation character, hence
          the comma character cannot be used in any string representation.
    """

    def __init__(self, name: str) -> None:
        IndexedTableSuperclass.__init__(self, name)
        self.keytable: Dict[Tuple[str, str], int] = {}  # key -> index
        self.indextable: Dict[int, IndexedTableValue] = {}  # index -> object
        self.next: int = 1
        self.reserved: List[int] = []
        self.checkpoint: Optional[int] = None

    def reset(self) -> None:
        self.keytable = {}
        self.indextable = {}
        self.next = 1
        self.reserved = []
        self.checkpoint = None

    def set_checkpoint(self) -> int:
        if self.checkpoint is None:
            self.checkpoint = self.next
            return self.next
        raise IndexedTableError(
            "Checkpoint has already been set at " + str(self.checkpoint))

    def iter(self, f: Callable[[int, IndexedTableValue], None]) -> None:
        for (i, v) in self.items():
            f(i, v)

    def reset_to_checkpoint(self) -> int:
        """Remove all entries added since the checkpoint was set."""
        cp = self.checkpoint
        if cp is None:
            raise UF.CHBError("Cannot reset non-existent checkpoint")
        for i in range(cp, self.next):
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

    def remove_checkpoint(self) -> None:
        self.checkpoint = None

    def add(
            self,
            key: Tuple[str, str],
            f: Callable[[int, Tuple[str, str]], IndexedTableValue]) -> int:
        if key in self.keytable:
            return self.keytable[key]
        else:
            index = self.next
            obj = f(index, key)
            self.keytable[key] = index
            self.indextable[index] = obj
            self.next += 1
            return index

    def reserve(self) -> int:
        index = self.next
        self.reserved.append(index)
        self.next += 1
        return index

    def keys(self) -> List[int]:
        return sorted(list(self.indextable.keys()))

    def values(self) -> List[IndexedTableValue]:
        result: List[IndexedTableValue] = []
        for i in sorted(self.indextable):
            result.append(self.indextable[i])
        return result

    def items(self) -> List[Tuple[int, IndexedTableValue]]:
        result: List[Tuple[int, IndexedTableValue]] = []
        for i in sorted(self.indextable):
            result.append((i, self.indextable[i]))
        return result

    def commit_reserved(
            self,
            index: int,
            key: Tuple[str, str], obj: IndexedTableValue) -> None:
        if index in self.reserved:
            self.keytable[key] = index
            self.indextable[index] = obj
            self.reserved.remove(index)
        else:
            raise IndexedTableError(
                "Trying to commit nonexisting index: " + str(index))

    def size(self) -> int:
        return (self.next - 1)

    def retrieve(self, index: int) -> IndexedTableValue:
        if index in self.indextable:
            return self.indextable[index]
        else:
            msg = (
                "Unable to retrieve item "
                + str(index)
                + " from table "
                + self.name
                + " (size: "
                + str(self.size())
                + ")")
            items = self.items()
            raise IndexedTableError(
                msg
                + "\n"
                + self.name
                + ", size: "
                + str(self.size()),
                itemlist=items)

    def retrieve_by_key(
            self,
            f: Callable[[Tuple[str, str]], bool]) -> List[
                Tuple[Tuple[str, str], IndexedTableValue]]:
        result: List[Tuple[Tuple[str, str], IndexedTableValue]] = []
        for key in self.keytable:
            if f(key):
                result.append((key, self.indextable[self.keytable[key]]))
        return result

    def write_xml(
            self,
            node: ET.Element,
            f: Callable[[ET.Element, IndexedTableValue], None],
            tag: str = "n") -> None:
        for key in sorted(self.indextable):
            snode = ET.Element(tag)
            f(snode, self.indextable[key])
            node.append(snode)

    def read_xml(
            self,
            node: Optional[ET.Element],
            tag: str,
            get_value: Callable[
                [ET.Element], IndexedTableValue] = lambda x: get_value(x),
            get_key: Callable[
                [IndexedTableValue], Tuple[str, str]] = lambda x: x.key,
            get_index: Callable[
                [IndexedTableValue], int] = lambda x: x.index) -> None:
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

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("\n" + self.name)
        for ix in sorted(self.indextable):
            lines.append(str(ix).rjust(4) + "  " + str(self.indextable[ix]))
        if len(self.reserved) > 0:
            lines.append("Reserved: " + str(self.reserved))
        if self.checkpoint is not None:
            lines.append("Checkpoint: " + str(self.checkpoint))
        return "\n".join(lines)
