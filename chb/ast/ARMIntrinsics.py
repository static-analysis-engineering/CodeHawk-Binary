# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021-2022 Aarno Labs LLC
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
"""Signatures for ARM intrinsics.

Signatures obtained from

ARM C Language Extensions (ACLE)
2021Q2
Date of issue: 02 July 2021

"""

from typing import Dict

import chb.ast.ASTNode as AST


class ARMIntrinsics:

    def __init__(self) -> None:
        self._intrinsics: Dict[str, AST.ASTVarInfo] = {}
        self._uint32_t = self.mk_integer_ikind_type("iuint")
        self._unsigned_int = self.mk_integer_ikind_type("iuint")

    def mk_integer_ikind_type(self, ikind: str) -> AST.ASTTypInt:
        return AST.ASTTypInt(ikind)

    @property
    def uint32_t(self) -> AST.ASTTyp:
        return self._uint32_t

    @property
    def unsigned_int(self) -> AST.ASTTyp:
        return self._unsigned_int

    @property
    def clz(self) -> AST.ASTVarInfo:
        """unsigned int __clz(uint32_t x);

        Returns the number of leading zero bits in x. When x is zero
        it returns the argument width, i.e., 32 or 64.
        ACLE pg 45
        """
        funargs = AST.ASTFunArgs([AST.ASTFunArg("x", self.uint32_t)])
        fsig = AST.ASTTypFun(self.unsigned_int, funargs)
        return AST.ASTVarInfo(
            "__clz", vtype=fsig, globaladdress=0, vdescr="arm intrinsic")

    @property
    def cls(self) -> AST.ASTVarInfo:
        """unsigned int __cls(uint32_t x);

        Returns the number of leading sign bits in x. When x is zero it
        returns the argument width - 1, i.e., 31 or 63.
        ACLE pg 45
        """
        funargs = AST.ASTFunArgs([AST.ASTFunArg("x", self.uint32_t)])
        fsig = AST.ASTTypFun(self.unsigned_int, funargs)
        return AST.ASTVarInfo(
            "__cls", vtype=fsig, globaladdress=0, vdescr="arm intrinsic")
    
    @property
    def rbit(self) -> AST.ASTVarInfo:
        """uint32_t __rbit(uint32_t x);

        Reverses the bits in x.
        ACLE pg 45
        """
        funargs = AST.ASTFunArgs([AST.ASTFunArg("x", self.uint32_t)])
        fsig = AST.ASTTypFun(self.uint32_t, funargs)
        return AST.ASTVarInfo(
            "__rbit", vtype=fsig, globaladdress=0, vdescr="arm intrinsic")
    
    @property
    def rev(self) -> AST.ASTVarInfo:
        """uint32_t __rev(uint32_t x);

        Reverses the byte order within a word.
        ACLE pg 45
        """
        funargs = AST.ASTFunArgs([AST.ASTFunArg("x", self.uint32_t)])
        fsig = AST.ASTTypFun(self.uint32_t, funargs)
        return AST.ASTVarInfo(
            "__rev", vtype=fsig, globaladdress=0, vdescr="arm intrinsic")

    @property
    def rev16(self) -> AST.ASTVarInfo:
        """uint32_t __rev16(uint32_t x);

        Reverses the byte order within each halfword of a word.
        ACLE pg 45
        """
        funargs = AST.ASTFunArgs([AST.ASTFunArg("x", self.uint32_t)])
        fsig = AST.ASTTypFun(self.uint32_t, funargs)
        return AST.ASTVarInfo(
            "__rev16", vtype=fsig, globaladdress=0, vdescr="arm intrinsic")

    @property
    def ror(self) -> AST.ASTVarInfo:
        """uint32_t __ror(uint32_t x, uint32_t y);

        Rotates the argument x right y bits. y can take any value.
        ACLE pg 44
        """
        funargs = AST.ASTFunArgs(
            [AST.ASTFunArg("x", self.uint32_t),
             AST.ASTFunArg("y", self.uint32_t)])
        fsig = AST.ASTTypFun(self.uint32_t, funargs)
        return AST.ASTVarInfo(
            "__ror", vtype=fsig, globaladdress=0, vdescr="arm intrinsic")
