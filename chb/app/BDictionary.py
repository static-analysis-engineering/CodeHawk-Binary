# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
# Copyright (c) 2020      Henny Sipma
# Copyright (c) 2021      Aarno Labs LLC
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
"""Dictionary for indexing basic data structures."""

import xml.etree.ElementTree as ET

from chb.app.BDictionaryRecord import bdregistry

from chb.app.ARMExtensionRegister import (
    ARMExtensionRegister,
    ARMExtensionRegisterElement,
    ARMExtensionRegisterReplicatedElement)

from chb.app.Register import Register
from chb.arm.ARMRegister import ARMRegister

import chb.util.fileutil as UF
import chb.util.IndexedTable as IT
import chb.util.StringIndexedTable as SI

from typing import Callable, List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    import chb.app.AppAccess


class AsmAddress(IT.IndexedTableValue):

    def __init__(self, ixvalue: IT.IndexedTableValue):
        IT.IndexedTableValue.__init__(
            self, ixvalue.index, ixvalue.tags, ixvalue.args)

    def get_hex(self) -> str:
        return(self.tags[0])

    def get_int(self) -> int:
        return int(self.tags[0], 16)

    def __str__(self) -> str:
        return self.get_hex()


class BDictionary:

    def __init__(
            self,
            app: "chb.app.AppAccess.AppAccess",
            xnode: ET.Element):
        self._app = app
        self.string_table = SI.StringIndexedTable('string-table')
        self.address_table = IT.IndexedTable('address-table')
        self.arm_extension_register_table = IT.IndexedTable(
            "arm-extension-register-table")
        self.arm_extension_register_element_table = IT.IndexedTable(
            "arm-extension-register-element-table")
        self.arm_extension_register_replicated_element_table = IT.IndexedTable(
            "arm-extension-register-replicated-element-table")
        self.register_table = IT.IndexedTable('register-table')
        self.tables: List[IT.IndexedTable] = [
            self.address_table,
            self.arm_extension_register_table,
            self.arm_extension_register_element_table,
            self.arm_extension_register_replicated_element_table,
            self.register_table]
        self.initialize(xnode)

    @property
    def app(self) -> "chb.app.AppAccess.AppAccess":
        return self._app

    # -------------- Retrieve items from dictionary tables ---------------------

    def string(self, ix: int) -> str:
        return self.string_table.retrieve(ix)

    def address(self, ix: int) -> AsmAddress:
        return AsmAddress(self.address_table.retrieve(ix))

    def arm_extension_register(self, ix: int) -> ARMExtensionRegister:
        return ARMExtensionRegister(
            self, self.arm_extension_register_table.retrieve(ix))

    def arm_extension_register_element(
            self, ix: int) -> ARMExtensionRegisterElement:
        return ARMExtensionRegisterElement(
            self, self.arm_extension_register_element_table.retrieve(ix))

    def arm_extension_register_replicated_element(
            self, ix: int) -> ARMExtensionRegisterReplicatedElement:
        return ARMExtensionRegisterReplicatedElement(
            self,
            self.arm_extension_register_replicated_element_table.retrieve(ix))

    def register(self, ix: int) -> Register:
        return bdregistry.mk_instance(
            self, self.register_table.retrieve(ix), Register)

    # ----------------------- xml accessors ------------------------------------

    def read_xml_string(self, n: ET.Element) -> str:
        index = n.get("istr")
        if index:
            return self.string(int(index))
        raise UF.CHBError("Error in reading from string table: tag missing")

    # ---------------- Initialize dictionary from file -------------------------

    def initialize(self, xnode: ET.Element) -> None:
        for t in self.tables:
            t.reset()
            xtable = xnode.find(t.name)
            if xtable is not None:
                t.read_xml(xtable, "n")
            else:
                if t.name.startswith("arm") and (not self.app.is_arm):
                    pass
                else:
                    raise UF.CHBError("Error reading table " + t.name)
        self.string_table.reset()
        xstable = xnode.find(self.string_table.name)
        if xstable is not None:
            self.string_table.read_xml(xstable)
        else:
            raise UF.CHError(
                "Error reading stringtable " + self.string_table.name)
