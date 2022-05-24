# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2022 Aarno Labs LLC
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
"""AST serialization to json format."""

from typing import Any, cast, Dict, List, Tuple


def get_key(tags: List[str], args: List[int]) -> Tuple[str, str]:
    return (",".join(tags), ",".join(str(i) for i in args))


class ASTNodeDictionary:

    def __init__(self) -> None:
        self.keytable: Dict[Tuple[str, str], int] = {}  # key -> index
        self.indextable: Dict[int, Dict[str, Any]] = {}  # index -> record
        self.next = 1

    def add(self, key: Tuple[str, str], node: Dict[str, Any]) -> int:
        if key in self.keytable:
            return self.keytable[key]
        else:
            index = self.next
            self.keytable[key] = index
            self.indextable[index] = node
            self.next += 1
            return index

    def records(self) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        for (id, record) in sorted(self.indextable.items()):
            record["id"] = id
            result.append(record)
        return result
