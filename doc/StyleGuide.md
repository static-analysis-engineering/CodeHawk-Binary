## CodeHawk-Binary Programming Style Guide

Naming conventions in part based on
[these guidelines](https://python-consistency.readthedocs.io/en/latest/conventions.html)

### Properties

#### Properties in favor of getters/setters

Getters and setters that are simple, e.g. no parameters in the getter and a single in the setter,
should be a property. However, if there are significant side effects to the getter or the setter,
that must be made clear to the programmer, use the function style.

#### Do not use get_

Prefer to use the name without the get_ prefix. This is in line with the use of properties, but
also when it is a method, prefer to use it without the prefix. Unless you also have a setter,
but then you would have used a property anyway. Conversely, set_ should be avoided as well,
but only if this is clear.

#### is__ is a property

If you have a method that is simply a def is_foo(self):, it is a property with that name.

#### Prefer using iterators, avoid iter_

Unless you need to distinguish between iterators and lists, you should avoid the prefix iter_.
Furthermore, if your code of returning a list is simply list(iter), avoid that method at all.
But if you have a list, return it. A list is iterable after all.


#### CodeHawk-Binary-specific guidelines

- Use properties for principal components that are created once and then cached. These
  include blocks, instructions, cfg belonging to functions, functions belonging to an
  application, etc. These may return immutable lists or dictionaries (Sequence or
  Mapping).

- Do not use properties for methods that return items that may or may not be available on
  the receiving class, and thus may raise an exception.

- Do not use properties for methods starting with has_