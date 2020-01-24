#!/usr/bin/env python3

import emulator
import sys


def emulate(fname, arch):
    program = open(fname, "rb").read() + b"\x90"*8
    e = emulator.Emulator(arch)
    e.run(program, hook_fn=e.print_code)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: {:s} FILE [x86_32|x86_64]".format(sys.argv[0]))
        sys.exit(1)

    emulate(sys.argv[1], sys.argv[2])
