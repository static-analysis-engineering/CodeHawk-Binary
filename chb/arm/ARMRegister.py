# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs LLC
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
"""Representation of ARM registers."""

from typing import TYPE_CHECKING

from chb.app.BDictionaryRecord import bdregistry
from chb.app.Register import Register

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.app.BDictionary


class ARMRegisterBase(Register):

    def __init__(
            self,
            bd: "chb.app.BDictionary.BDictionary",
            ixval: IndexedTableValue) -> None:
        Register.__init__(self, bd, ixval)


@bdregistry.register_tag("a", Register)
class ARMRegister(ARMRegisterBase):

    def __init__(self,
                 bd: "chb.app.BDictionary.BDictionary",
                 ixval: IndexedTableValue) -> None:
        ARMRegisterBase.__init__(self, bd, ixval)

    def __str__(self) -> str:
        return self.tags[1]
