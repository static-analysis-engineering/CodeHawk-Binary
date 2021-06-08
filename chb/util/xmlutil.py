# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
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

import xml.etree.ElementTree as ET
import datetime
import os

from typing import Any, Dict, List


def get_codehawk_xml_header(filename: str, info: str) -> ET.Element:
    root = ET.Element("codehawk-binary-analyzer")
    tree = ET.ElementTree(root)
    header = ET.Element("header")
    header.set("info", info)
    header.set("name", filename)
    header.set("time", str(datetime.datetime.now()))
    root.append(header)
    return root


def attributes_to_pretty(attr: Dict[str, str], indent: int = 0) -> str:
    if len(attr) == 0:
        return ""
    if len(attr) > 4:
        lines: List[str] = []
        for key in sorted(attr):
            lines.append(((' ' * (indent + 2)) + key + '="' + attr[key] + '"'))
        return ('\n' + '\n'.join(lines))
    else:
        return (' ' + ' '.join(key + '="' + attr[key] + '"' for key in sorted(attr)))


def element_to_pretty(e: ET.Element, indent: int = 0) -> List[str]:
    lines: List[str] = []
    attrs = attributes_to_pretty(e.attrib, indent)
    ind = " " * indent
    if e.text is None:
        children = list(e.findall("*"))
        if children == []:
            lines.append(ind + "<" + e.tag + attrs + "/>\n")
            return lines
        else:
            lines.append(ind + "<" + e.tag + attrs + ">\n")
            for c in children:
                lines.extend(element_to_pretty(c, indent + 2))
            lines.append(ind + "</" + e.tag + ">\n")
            return lines
    else:
        lines.append(
            ind + "<" + e.tag + attrs + ">" + e.text + "</" + e.tag + ">\n")
    return lines


def doc_to_pretty(t: ET.ElementTree) -> str:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>\n']
    lines.extend(element_to_pretty(t.getroot()))
    return "".join(lines)


def create_xml_section_header_userdata(d: Dict[str, Any]) -> ET.Element:
    root = ET.Element("section-headers")
    for section in d:
        sh = ET.Element("sh")
        root.append(sh)
        sh.set("name", section)
        for attr in d[section]:
            fld = ET.Element("fld")
            sh.append(fld)
            fld.set("name", attr)
            fld.set("value", d[section][attr])
    return root


def create_xml_userdata(d: Dict[str, Any]) -> List[ET.Element]:
    result: List[ET.Element] = []
    if "section-headers" in d:
        result.append(create_xml_section_header_userdata(d["section-headers"]))
    return result
