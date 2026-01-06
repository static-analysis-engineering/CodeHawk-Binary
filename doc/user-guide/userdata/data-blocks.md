### Data blocks

**Description**

Code sections may interleave code with data regions. This is particularly common
in ARM binaries. Most of these data regions are detected automatically by the
disassembler. For the cases where this fails the user can point out these data
regions in the userdata with the data-blocks section.

**Format**

A list of records that specify the start (inclusive) and end (exclusive) address
of a data region, where the record has the format:
```
    {"r": [<start-address>, <end-address>]}
```


**Example**

```
{
    "userdata": {
        ....
        "data-blocks": [
            {"r": ["0xa02425fc", "0xa0242674"]},
            {"r": ["0xa0255e68", "0xa0255e94"]},
            {"r": ["0xa03005d4", "0xa03005f8"]},
            {"r": ["0xa0300a9e", "0xa0300ab0"]},
            ...
         ]
    }
}
```    