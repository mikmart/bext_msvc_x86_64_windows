# MSVC Bext Codegen

An MSVC codegen plugin for [bext-lang/b](https://github.com/bext-lang/b).
It generates [MASM](https://learn.microsoft.com/en-us/cpp/assembler/masm/microsoft-macro-assembler-reference?view=msvc-170) assembly, which has some peculiarities. See below.

When used with an MSVC build of the compiler, this plugin lets you work on Windows without the need for a GNU toolchain. For the time being must be used with [mikmart/b@msvc](https://github.com/mikmart/b/tree/msvc) to compile the compiler with MSVC.

## Installation

``` console
$ git clone -b msvc https://github.com/mikmart/b.git
$ cd b/src/codegen
$ git clone https://github.com/mikmart/bext_msvc_x86_64_windows.git
$ cd ../..
$ cl nob.c
$ .\nob
$ .\build\b -tlist
$ .\build\b -t msvc-x86_64-windows .\examples\hello_world.b -run
```

## Requirements

`ml64` and `link` in your `PATH`. See [Microsoft documentation](https://learn.microsoft.com/en-us/cpp/build/building-on-the-command-line?view=msvc-170) for setting up your environment.

## Limitations

MASM has a lot of reserved words, and no proper escape hatch to use them as names.
To work around this, names in the generated assembly are mangled. There are 2 implications:

* Any inline assembly code in B must prefix names with `?`; e.g. `call printf` becomes `call ?printf`.
* Still not all names can be used; in particular the keywords required to implement the mangling scheme.
