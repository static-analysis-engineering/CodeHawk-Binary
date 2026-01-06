### Call-back Tables

**Description**

Call-back tables are arrays of structs in global memory that contain related
function pointers, usually associated with some other identifying data.
Common examples of call-back tables are in binaries that serve requests based
on a particular keyword. In such systems the response to the request is often
invoked by matching the key to the identifying key in the table and executing
the associated function pointer.

The userdata representation for such call-back tables consists of three elements:
1. The definition of the table in C (in the C header file)
2. The start address of the table in memory (in userdata)
3. The addresses of the indirect calls into the table (in userdata)

This section only shows the format for (2). The addresses of the indirect
calls are specified in a separate section, described in
[call-targets](call-targets.md).


**Format**

A table of virtual addresses in memory mapped to names of defined tables.


**Example**

```
{
    "userdata": {
        ....
	"call-back-tables": {
	    "0x4a5910": "request_table",
	    "0x4a5c30": "cgi_setobject_table"
	}
    }
}
```

This section must be accompanied by a definition of the corresponding table
in a header file that is passed to the analyzer at the same time. The
corresponding header definition in this case could be something like:

```
struct _cbt_http_request {
  char *formname;
  char *filetype;
  char *cachecontrol;
  int (*cpb_request_12)(void *state, void *stream, int len);
  int (*cbp_request_16)(char *filename, void *stream);
  int (*cbp_request_20)(char *level);
} cbt_http_request;


struct _cbt_http_request *request_table;


struct _cbt_cgi_setobject {
  char *tag;
  int num;
  int (*cbp_cgi_setobject)(struct keyvaluepair_t *kvp, int len);
} cbt_cgi_setobject;


struct _cbt_cgi_setobject *cgi_setobject_table;
```



        