# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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

from typing import Any, Dict, List, Optional, Union


class JSONStackpointerOffset:

    def __init__(self, d: Dict[str, Any]) -> None:
        self._d = d

    @property
    def d(self) -> Dict[str, Any]:
        return self._d

    @property
    def txtrep(self) -> str:
        return self.d.get("txtrep", "missing:stackpointeroffset:txtrep")


class JSONStackpointerOffsetUnknown(JSONStackpointerOffset):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONStackpointerOffset.__init__(self, d)


class JSONStackpointerOffsetSingleton(JSONStackpointerOffset):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONStackpointerOffset.__init__(self, d)

    @property
    def value(self) -> int:
        return int(self.d.get("value", -11111111))


class JSONStackpointerOffsetInterval(JSONStackpointerOffset):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONStackpointerOffset.__init__(self, d)

    @property
    def lb(self) -> int:
        return int(self.d.get("lb", -11111111))

    @property
    def upper_bound(self) -> int:
        return int(self.d.get("ub", -11111111))


class JSONStackpointerOffsetLowerBound(JSONStackpointerOffset):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONStackpointerOffset.__init__(self, d)

    @property
    def lb(self) -> int:
        return int(self.d.get("lb", -11111111))


class JSONStackpointerOffsetUpperBound(JSONStackpointerOffset):

    def __init__(self, d: Dict[str, Any]) -> None:
        JSONStackpointerOffset.__init__(self, d)

    @property
    def ub(self) -> int:
        return int(self.d.get("ub", -11111111))

                   
def mk_stackpointer_offset(d: Dict[str, Any]) -> JSONStackpointerOffset:

    kind = d.get("kind", "unb-itv")

    if kind == "civ":
        return JSONStackpointerOffsetSingleton(d)
    elif kind == "itv":
        return JSONStackpointerOffsetInterval(d)
    elif kind == "lb-itv":
        return JSONStackpointerOffsetLowerBound(d)
    elif kind == "ub-itv":
        return JSONStackpointerOffsetUpperBound(d)
    else:
        return JSONStackpointerOffsetUnknown(d)
        
        
