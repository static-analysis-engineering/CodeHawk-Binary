# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2026  Aarno Labs LLC
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


from typing import List, TYPE_CHECKING

from chb.api.InterfaceDictionaryRecord import (
    InterfaceDictionaryRecord, apiregistry)

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    from chb.api.InterfaceDictionary import InterfaceDictionary


class FormatStringType(InterfaceDictionaryRecord):

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        InterfaceDictionaryRecord.__init__(self, ixd, ixval)

    @property
    def is_input_formatstring(self) -> bool:
        return False

    @property
    def is_output_formatstring(self) -> bool:
        return False

    @property
    def is_restricted_output_formatstring(self) -> bool:
        return False


@apiregistry.register_tag("s", FormatStringType)
class ScanFormatStringType(FormatStringType):

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        FormatStringType.__init__(self, ixd, ixval)

    @property
    def is_input_formatstring(self) -> bool:
        return True

    def __str__(self) -> str:
        return "scanformat"


@apiregistry.register_tag("p", FormatStringType)
class PrintFormatStringType(FormatStringType):

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        FormatStringType.__init__(self, ixd, ixval)

    @property
    def is_output_formatstring(self) -> bool:
        return True

    def __str__(self) -> str:
        return "printformat"


@apiregistry.register_tag("rp", FormatStringType)
class RestrictedPrintFormatStringType(FormatStringType):

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        FormatStringType.__init__(self, ixd, ixval)

    @property
    def is_restricted_output_formatstring(self) -> bool:
        return True

    @property
    def specifiers(self) -> List[str]:
        return self.tags[1:]

    def __str__(self) -> str:
        return "restricted-printformat(" + ",".join(self.specifiers) + ")"


@apiregistry.register_tag("n", FormatStringType)
class NoFormatStringType(FormatStringType):

    def __init__(
            self, ixd: "InterfaceDictionary", ixval: IndexedTableValue) -> None:
        FormatStringType.__init__(self, ixd, ixval)

    @property
    def is_no_formatstring(self) -> bool:
        return True

    def __str__(self) -> str:
        return "printformat"
