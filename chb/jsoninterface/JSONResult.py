# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2023  Aarno Labs LLC
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
"""Intermediate json format to return structured data for output (immutable)."""

from typing import Any, Callable, Dict, Optional


class JSONResult:

    def __init__(
            self,
            schemaref: str,
            content: Dict[str, Any],
            status: str,
            reason: Optional[str] = None) -> None:
        self._schemaref = schemaref
        self._content = content
        self._status = status
        self._reason = reason

    @property
    def schemaref(self) -> str:
        return self._schemaref

    @property
    def content(self) -> Dict[str, Any]:
        return self._content

    @property
    def status(self) -> str:
        return self._status

    @property
    def reason(self) -> Optional[str]:
        return self._reason

    @property
    def is_ok(self) -> bool:
        return self.status == "ok"
