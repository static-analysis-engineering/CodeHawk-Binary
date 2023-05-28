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
"""Schema to describe json data."""

from typing import Any, Callable, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from chb.jsoninterface.JSONSchemaRegistry import JSONSchemaRegistry


class JSONSchema:

    def __init__(
            self,
            name: str,
            base_schema: Dict[str, Any],
            defs: Dict[str, Dict[str, Any]] = {}) -> None:
        self._name = name
        self._base_schema = base_schema
        self._defs = defs

    @property
    def name(self) -> str:
        return self._name

    @property
    def base_schema(self) -> Dict[str, Any]:
        return self._base_schema

    @property
    def defs(self) -> Dict[str, Dict[str, Any]]:
        return self._defs

    def set_defs(self, defs: Dict[str, Dict[str, Any]]) -> None:
        self._defs = defs

    def to_json(self) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        return (self.base_schema, self.defs)
