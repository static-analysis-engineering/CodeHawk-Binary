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
"""ARM SIMD writeback and elements.

                                                   tags[0]  tags   args
type arm_simd_writeback_t =
  | SIMDNoWriteback                                  "n"      1      0
  | SIMDBytesTransferred of int                      "b"      1      1
  | SIMDAddressOffsetRegister of arm_reg_t           "r"      2      0


type arm_simd_list_element_t =
  | SIMDReg of arm_extension_register_t              "r"      1      1
  | SIMDRegElement of                                "e"      1      1
        arm_extension_register_element_t
  | SIMDRegRepElement of                             "re"     1      1
        arm_extension_register_replicated_element_t

"""

from typing import List, TYPE_CHECKING

from chb.arm.ARMDictionaryRecord import ARMDictionaryRecord, armregistry

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.app.ARMExtensionRegister import (
        ARMExtensionRegister,
        ARMExtensionRegisterElement,
        ARMExtensionRegisterReplicatedElement)
    from chb.app.BDictionary import BDictionary
    from chb.arm.ARMDictionary import ARMDictionary


class ARMSIMDWriteback(ARMDictionaryRecord):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)

    @property
    def is_no_writeback(self) -> bool:
        return False

    @property
    def is_bytes_transferred(self) -> bool:
        return False

    @property
    def is_address_offset(self) -> bool:
        return False

    def __str__(self) -> str:
        return "simd_writeback: " + self.tags[0]


@armregistry.register_tag("n", ARMSIMDWriteback)
class ARMSIMDNoWriteback(ARMSIMDWriteback):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMSIMDWriteback.__init__(self, d, ixval)

    @property
    def is_no_writeback(self) -> bool:
        return True

    def __str__(self) -> str:
        return ""


@armregistry.register_tag("b", ARMSIMDWriteback)
class ARMSIMDBytesTransferred(ARMSIMDWriteback):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMSIMDWriteback.__init__(self, d, ixval)

    @property
    def is_bytes_transferred(self) -> bool:
        return True

    def __str__(self) -> str:
        return ""


@armregistry.register_tag("r", ARMSIMDWriteback)
class ARMSIMDAddressOffsetRegister(ARMSIMDWriteback):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMSIMDWriteback.__init__(self, d, ixval)

    @property
    def offsetregister(self) -> str:
        return self.tags[1]

    @property
    def is_address_offset(self) -> bool:
        return True

    def __str__(self) -> str:
        return self.offsetregister


class ARMSIMDListElement(ARMDictionaryRecord):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)

    def __str__(self) -> str:
        return "simd-list-element: " + self.tags[0]


@armregistry.register_tag("r", ARMSIMDListElement)
class ARMSIMDReg(ARMSIMDListElement):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMSIMDListElement.__init__(self, d, ixval)

    @property
    def xregister(self) -> "ARMExtensionRegister":
        return self.bd.arm_extension_register(self.args[0])

    def __str__(self) -> str:
        return str(self.xregister)


@armregistry.register_tag("e", ARMSIMDListElement)
class ARMSIMDRegElement(ARMSIMDListElement):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMSIMDListElement.__init__(self, d, ixval)

    @property
    def xregelement(self) -> "ARMExtensionRegisterElement":
        return self.bd.arm_extension_register_element(self.args[0])

    def __str__(self) -> str:
        return str(self.xregelement)


@armregistry.register_tag("re", ARMSIMDListElement)
class ARMSIMDRegRepElement(ARMSIMDListElement):

    def __init__(
            self,
            d: "ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMSIMDListElement.__init__(self, d, ixval)

    @property
    def xrepelement(self) -> "ARMExtensionRegisterReplicatedElement":
        return self.bd.arm_extension_register_replicated_element(self.args[0])

    def __str_(self) -> str:
        return str(self.xrepelement)
