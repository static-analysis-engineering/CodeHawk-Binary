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
"""ARM Vector Floating Point data types.

Corresponds to arm_vfp_datatype_t in bchlibarm32/BCHARMTypes:

                                                   tags[0]   tags   args
type arm_vfp_datatype_t =
  | VfpNone                                          "n"       1      1
  | VfpSize of int                                   "z"       1      1
  | VfpFloat of int                                  "f"       1      1
  | VfpInt of int                                    "i"       1      1
  | VfpPolynomial of int                             "p"       1      1
  | VfpSignedInt of int                              "s"       1      1
  | VfpUnsignedInt of int                            "u"       1      1
"""

from typing import List, TYPE_CHECKING

from chb.arm.ARMDictionaryRecord import ARMDictionaryRecord, armregistry

import chb.util.fileutil as UF

from chb.util.IndexedTable import IndexedTableValue

if TYPE_CHECKING:
    import chb.arm.ARMDictionary


class ARMVfpDatatype(ARMDictionaryRecord):

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMDictionaryRecord.__init__(self, d, ixval)

    @property
    def size(self) -> int:
        if len(self.args) > 0:
            return self.args[0]
        else:
            raise UF.CHBError(
                "Vfp datatype has no size: "
                + str(self))

    def __str_(self) -> str:
        return "vfp-datatype: " + self.tags[0]


@armregistry.register_tag("n", ARMVfpDatatype)
class ARMVfpNone(ARMVfpDatatype):
    """No vfp data type."""

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMVfpDatatype.__init__(self, d, ixval)

    def __str__(self) -> str:
        return ""


@armregistry.register_tag("z", ARMVfpDatatype)
class ARMVfpSize(ARMVfpDatatype):
    """Size only.

    args[0]: size (in bits)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMVfpDatatype.__init__(self, d, ixval)

    def __str__(self) -> str:
        return "." + str(self.size)


@armregistry.register_tag("f", ARMVfpDatatype)
class ARMVfpFloat(ARMVfpDatatype):
    """Floating point number (single or double-precision).

    args[0]: size (in bits)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMVfpDatatype.__init__(self, d, ixval)

    def __str__(self) -> str:
        return ".F" + str(self.size)


@armregistry.register_tag("i", ARMVfpDatatype)
class ARMVfpInt(ARMVfpDatatype):
    """Integer number (single or double-precision).

    args[0]: size (in bits)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMVfpDatatype.__init__(self, d, ixval)

    def __str__(self) -> str:
        return ".I" + str(self.size)


@armregistry.register_tag("p", ARMVfpDatatype)
class ARMVfpPolynomial(ARMVfpDatatype):
    """Polynomial value.

    args[0]: size (in bits)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMVfpDatatype.__init__(self, d, ixval)

    def __str__(self) -> str:
        return ".P" + str(self.size)


@armregistry.register_tag("s", ARMVfpDatatype)
class ARMVfpSignedInt(ARMVfpDatatype):
    """Signed integer (single or double precision).

    args[0]: size (in bits)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMVfpDatatype.__init__(self, d, ixval)

    def __str__(self) -> str:
        return ".S" + str(self.size)


@armregistry.register_tag("u", ARMVfpDatatype)
class ARMVfpUnsignedInt(ARMVfpDatatype):
    """UnsignedInt (single or double precision).

    args[0]: size (in bits)
    """

    def __init__(
            self,
            d: "chb.arm.ARMDictionary.ARMDictionary",
            ixval: IndexedTableValue) -> None:
        ARMVfpDatatype.__init__(self, d, ixval)

    def __str__(self) -> str:
        return ".U" + str(self.size)
