#!/usr/bin/env python3

from unicorn import *
from unicorn.x86_const import *
import capstone

from hexdump import hexdump

class Emulator():
    """
    program = open("/tmp/bbb", "rb").read() + b"\x90"*8
    Emulator("x86_32").run(program)
    """
    def __init__(self, arch, show_output=True):
        self.text_base = 0x0000
        self.stack_base = 0xfffdd000
        self.stack_size = 0x21000
        self.show_output = show_output

        if arch == "x86_32":
            self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.ip = UC_X86_REG_EIP
            self.sp = UC_X86_REG_ESP
        if arch == "x86_64":
            self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.ip = UC_X86_REG_RIP
            self.sp = UC_X86_REG_RSP

        self.mu.mem_map(self.text_base, 0x10000)
        self.mu.mem_map(self.stack_base, self.stack_size)

    def hook_code(self, mu, address, size, user_data):
        inst = mu.mem_read(address, size)

        for dis in self.md.disasm(inst, size):
            if self.show_output:
                print(hex(address),
                        "{:16x}".format(int.from_bytes(mu.mem_read(address, size), byteorder='little')),
                        "\t",
                        dis.mnemonic,
                        dis.op_str)
            if dis.mnemonic.startswith("int"):
                mu.reg_write(self.ip, address + size)


    def run(self, code):
        self.mu.mem_write(self.text_base, code)
        self.mu.reg_write(self.sp, self.stack_base + self.stack_size)

        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)
        if self.show_output:
            print("[+] - Starting emulation")
        self.mu.emu_start(self.text_base, len(code))

        esp = self.mu.reg_read(self.sp)
        stack_contents = bytes(self.mu.mem_read(esp, self.stack_base + self.stack_size - 16 - esp))
        if self.show_output:
            print("STACK <{} bytes>: ".format(len(stack_contents)))
            hexdump(stack_contents)

        return self.mu
