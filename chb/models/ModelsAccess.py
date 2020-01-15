# ------------------------------------------------------------------------------
# Access to the CodeHawk Binary Analyzer Analysis Results
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2016-2020 Kestrel Technology LLC
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

import os
import zipfile
import xml.etree.ElementTree as ET

import chb.util.fileutil as UF

from chb.util.Config import Config
from chb.models.StdPESummaries import StdPESummaries
from chb.models.DllSummaries import DllSummaries


class ModelsAccess(object):
    """Main entry point for library function summaries."""

    def __init__(self,app,dlljars=[],elfjars=[]):
        """Initialize library models access with jarfile."""
        self.app = app
        self.dlljars = [ DllSummaries(self,d) for d in dlljars ]
        self.elfjars = elfjars
        self.stdpesummaries = StdPESummaries(self,Config().summaries)

    def has_dll_summary(self,dll,fname):
        return (self.stdpesummaries.has_summary(dll,fname)
                    or any([ dlljar.has_summary(dll,fname) for dlljar in self.dlljars ]))

    def get_dll_summary(self,dll,fname):
        if self.stdpesummaries.has_summary(dll,fname):
            return self.stdpesummaries.get_summary(dll,fname)
        for dlljar in self.dlljars:
            if dlljar.has_summary(dll,fname):
                return dlljar.get_summary(dll,fname)
        else:
            raise UF.CHBError('Summary for ' + dll + ', ' + fname + ' not found')

