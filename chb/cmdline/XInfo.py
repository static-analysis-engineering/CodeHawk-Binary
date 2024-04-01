#!/usr/bin/env python3
# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2023  Aarno Labs, LLC
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
"""Obtain and represent file information about executable."""

import os
import subprocess

from typing import Any, Dict, List, Union

import chb.util.Config as C
import chb.util.fileutil as UF


def get_md5(fname: str) -> str:
    config = C.Config()
    if config.platform == "linux":
        md5 = subprocess.run(['md5sum', fname], stdout=subprocess.PIPE)
        return md5.stdout.decode('utf-8')[:32]
    elif config.platform == "macOS":
        md5 = subprocess.run(["md5", fname], stdout=subprocess.PIPE)
        return md5.stdout.decode("utf-8")[-33:-1]
    else:
        raise UF.CHBError("Environment not recognized: " + config.platform)


def get_architecture(ftype: str) -> str:
    if "MIPS" in ftype:
        return "mips"
    if "ARM" in ftype:
        return "arm"
    if "80386" in ftype:
        return "x86"
    if "x86-64" in ftype:
        return "x64"
    if "PowerPC" in ftype:
        return "power"
    return "power"


def get_file_format(ftype: str) -> str:
    if "ELF" in ftype:
        return "elf"
    if "PE32" in ftype:
        return "pe32"
    return "?"


class XInfo:

    def __init__(self) -> None:
        self.fileinfo: Dict[str, Union[str, str]] = {}

    def discover(self, path: str, xfile: str) -> None:
        name = os.path.join(path, xfile)
        ftype = subprocess.run(["file", name], stdout=subprocess.PIPE)
        filetype = ftype.stdout.decode("utf-8")
        self.fileinfo["md5"] = get_md5(name)
        self.fileinfo["path"] = path
        self.fileinfo["file"] = xfile
        self.fileinfo["size"] = str(os.path.getsize(name))
        self.fileinfo["arch"] = get_architecture(filetype)
        self.fileinfo["format"] = get_file_format(filetype)

    def load(self, path: str, xfile: str) -> None:
        self.fileinfo = UF.get_xinfo_json(path, xfile)

    def save(self, path: str, xfile: str) -> None:
        UF.save_xinfo_json(path, xfile, self.fileinfo)

    @property
    def path(self) -> str:
        return self.fileinfo["path"]

    @property
    def file(self) -> str:
        return self.fileinfo["file"]

    @property
    def size(self) -> int:
        return int(self.fileinfo["size"])

    @property
    def md5(self) -> str:
        return self.fileinfo["md5"]

    @property
    def architecture(self) -> str:
        return self.fileinfo["arch"]

    @property
    def format(self) -> str:
        return self.fileinfo["format"]

    @property
    def is_mips(self) -> bool:
        return self.architecture == "mips"

    @property
    def is_arm(self) -> bool:
        return self.architecture == "arm"

    @property
    def is_x86(self) -> bool:
        return self.architecture == "x86"

    @property
    def is_power(self) -> bool:
        return self.architecture == "power"

    @property
    def is_elf(self) -> bool:
        return self.format == "elf"

    @property
    def is_pe32(self) -> bool:
        return self.format == "pe32"

    def __str__(self) -> str:
        lines: List[str] = []
        lines.append("md5   : " + self.md5)
        lines.append("path  : " + self.path)
        lines.append("file  : " + self.file)
        lines.append("size  : " + str(self.size))
        lines.append("arch  : " + self.architecture)
        lines.append("format: " + self.format)
        return "\n".join(lines)
