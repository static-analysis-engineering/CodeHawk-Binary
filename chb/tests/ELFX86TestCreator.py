# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
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
import datetime
import json
import xml.etree.ElementTree as ET

from typing import Dict, Mapping

import chb.util.fileutil as UF
import chb.util.xmlutil as UX


class ELFX86TestCreator:
    """Creates the three files that make up an x86 elf test case.

    test_xxx_elf_header.xml
    test_xxx_section_16.xml  (.text section)
    test_xxx_xinfo.json
    """

    def __init__(self, name: str, codesize: str, suite: str = "001") -> None:
        self._name = "test_" + name
        self._suite = "suite_" + suite
        self._codesize = codesize

    @property
    def name(self) -> str:
        return self._name

    @property
    def suite(self) -> str:
        return self._suite

    @property
    def size(self) -> str:
        return self._codesize

    def get_section_header(self) -> ET.Element:
        xsh = ET.Element("section-header")
        xsh.set("name", ".text")
        xsh.set("sh_addr", "0x1000")
        xsh.set("sh_addralign", "0x10")
        xsh.set("sh_flags", "0x6")
        xsh.set("sh_name", "0x0")
        xsh.set("sh_offset", "0x1000")
        xsh.set("sh_size", self.size)
        xsh.set("sh_type", "0x1")
        return xsh

    def create_elf_header(self) -> str:
        root = UX.get_codehawk_xml_header(self.name, "elf-header")
        xelfheader = ET.Element("elf-header")
        xfh = ET.Element("elf-file-header")
        xfh.set("e_ehsize", "52")
        xfh.set("e_entry", "0x1000")
        xfh.set("e_machine", "3")
        xfh.set("e_phentsize", "32")
        xfh.set("e_phnum", "0")
        xfh.set("e_phoff", "0x34")
        xfh.set("e_shentsize", "40")
        xfh.set("e_shnum", "1")
        xfh.set("e_shoff", "0x0")
        xfh.set("e_shstrndx", "0")
        xfh.set("e_type", "3")
        xfh.set("e_version", "0x1")
        xph = ET.Element("elf-program-headers")
        xsh = ET.Element("elf-section-headers")
        xsh16 = ET.Element("section-header")
        xsh16 = self.get_section_header()
        xsh16.set("index", "16")
        xsh.append(xsh16)
        xelfheader.append(xfh)
        xelfheader.append(xph)
        xelfheader.append(xsh)
        root.append(xelfheader)
        tree = ET.ElementTree(root)
        return UX.doc_to_pretty(tree)

    def create_elf_section(self, bytestring: str) -> str:
        root = UX.get_codehawk_xml_header(self.name, "raw-section")
        xsec = ET.Element("raw-section")
        xsec.set("index", "16")
        xsec.set("size", str(int(self.size, 16)))
        xsec.set("vaddr", "0x1000")
        xhex = ET.Element("hex-data")
        xhex.set("blocks", "1")
        xblock = ET.Element("ablock")
        xblock.set("block", "0")
        xline = ET.Element("aline")
        xline.set("bytes", bytestring)
        xline.set("print", "..")
        xline.set("va", "0x1000")
        xblock.append(xline)
        xhex.append(xblock)
        xsec.append(xhex)
        xsh = self.get_section_header()
        xsec.append(xsh)
        root.append(xsec)
        tree = ET.ElementTree(root)
        return UX.doc_to_pretty(tree)

    def create_xinfo(self) -> Mapping[str, str]:
        xinfo: Dict[str, str] = {}
        xinfo["md5"] = "77c2a94231d2b15d857e08f24e8a74a9"
        xinfo["path"] = "CodeHawk-Binary/tests/x86/elf/" + self.suite
        xinfo["file"] = self.name
        xinfo["size"] = str(int(self.size, 16))
        xinfo["arch"] = "x86"
        xinfo["format"] = "elf"
        return xinfo


if __name__ == "__main__":

    tc = ELFX86TestCreator("001", "0x10")

    print(tc.create_elf_header())

    print(tc.create_elf_section("c3909090 90909090 90909090 90909090 "))

    print(json.dumps(tc.create_xinfo()))
