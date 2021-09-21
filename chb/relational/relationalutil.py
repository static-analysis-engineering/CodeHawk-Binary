# ------------------------------------------------------------------------------
# CodeHawk Binary Analyzer
# Author: Henny Sipma
# ------------------------------------------------------------------------------
# The MIT License (MIT)
#
# Copyright (c) 2021 Aarno Labs, LLC
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
"""Utilities for relational analysis."""

from typing import List, Optional, Tuple


def levenshtein(
        s1: List[str],
        s2: List[str]) -> List[Tuple[Optional[int], Optional[int]]]:
    """Return a mapping from s1 to s2 that requires minimum transformations.

    Algorithm by Levenshtein (1965).
    """

    m: List[List[int]] = []
    size_x = len(s1) + 1
    size_y = len(s2) + 1

    for i in range(0, size_x):
        m.append([])
        for j in range(0, size_y):
            m[i].append(0)

    for x in range(0, size_x):
        m[x][0] = x
    for y in range(0, size_y):
        m[0][y] = y

    for x in range(1, size_x):
        for y in range(1, size_y):
            if s1[x-1] == s2[y-1]:
                m[x][y] = min(m[x-1][y] + 1, m[x-1][y-1], m[x][y-1] + 1)
            else:
                m[x][y] = min(m[x-1][y] + 1, m[x-1][y-1] + 1, m[x][y-1] + 1)

    edits: List[Tuple[int, int, str]] = []
    mapping: List[Tuple[Optional[int], Optional[int]]] = []

    x = size_x - 1
    y = size_y - 1
    mval = m[x][y]
    pmval = mval

    while x > 0 and y > 0:
        mc = m[x-1][y-1]
        ml = m[x-1][y]
        mr = m[x][y-1]

        if mc < pmval:    # substitution
            edits.append((x-1, y-1, "s"))
            x = x - 1
            y = y - 1
            pmval = mc
            mapping.append((x, y))

        elif ml < pmval:   # deletion
            edits.append((x-1, y, "d"))
            x = x - 1
            pmval = ml
            mapping.append((x, None))

        elif mr < pmval:   # insertion
            edits.append((x, y-1, "i"))
            y = y - 1
            pmval = mr
            mapping.append((None, y))

        else:      # no change
            x = x - 1
            y = y - 1
            pmval = mval
            mapping.append((x, y))

        mval = m[x][y]

    return mapping
