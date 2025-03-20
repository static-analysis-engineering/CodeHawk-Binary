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

from typing import TYPE_CHECKING

import chb.models.FunctionSummaryLibrary as L

if TYPE_CHECKING:
    import chb.models.SummaryCollection


class JniFunctionSummaryLibrary(L.FunctionSummaryLibrary):
    """Collection of java native method summaries.

    Native methods are indexed by numbers, roughly through 231. Many of these
    methods are similar, differring only in the type to which they are
    applicable. The summaries in the bchsummaries archive make use of templates that
    can be instantiated for these different types.

    For example, for jni_190.xml:

      <jnifun index="190">
         <refer-to typename="Double" prefix="Get" suffix="ArrayElements">
             <replace-type src="ttype" tgt="jdouble"/>
             <replace-type src="atype" tgt="jdoubleArray"/>
         </refer-to>
      </jnifun>

    which refers to the template summary GetArrayElements, with signature:

      <api adj="12" cc="stdcall" name="GetArrayElements">
         <par loc="stack" desc="jni interface pointer" io="r" name="env" nr="1">
            <type><ptr>JNIEnv</ptr></type>
            <pre><deref-read/></pre>
         </par>
         <par loc="stack" desc="java array" io="r" name="array" nr="2">
            <type>atype</type>
            <roles>
              <role rt="jni:array" rn="retrieve elements"/>
            </roles>
         </par>
         <par loc="stack" name="isCopy" nr="3">
            <type><ptr>jboolean</ptr></type>
            <pre><deref-write/></pre>
            <sideeffects><block-write/></sideeffects>
         </par>
         <returntype>ttype</returntype>
      </api>
    """

    def __init__(
            self,
            summarycollection: "chb.models.SummaryCollection.SummaryCollection",
            directory: str,
            name: str) -> None:
        L.FunctionSummaryLibrary.__init__(self, summarycollection, directory, name)

    @property
    def is_jni_library(self) -> bool:
        return True

    @property
    def libfun_xmltag(self) -> str:
        return "jnifun"
