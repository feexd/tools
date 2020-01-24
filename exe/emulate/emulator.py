#!/usr/bin/env python3

from unicorn import *
from unicorn.x86_const import *
import capstone
import functools

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
        self.arch = arch
        self.hooks = [self.print_code_and_registers, self.print_code]

        if arch == "x86_32":
            self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.regs = {
                    "ip": UC_X86_REG_EIP,
                    "sp": UC_X86_REG_ESP,
                    "ax": UC_X86_REG_EAX,
                    "bx": UC_X86_REG_EBX,
                    "cx": UC_X86_REG_ECX,
                    "dx": UC_X86_REG_EDX,
                    "di": UC_X86_REG_EDI,
                    "si": UC_X86_REG_ESI,
                    "bp": UC_X86_REG_EBP,
                    "sp": UC_X86_REG_ESP}
        if arch == "x86_64":
            self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
            self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self.regs = {
                    "ip": UC_X86_REG_RIP,
                    "sp": UC_X86_REG_RSP,
                    "ax": UC_X86_REG_RAX,
                    "bx": UC_X86_REG_RBX,
                    "cx": UC_X86_REG_RCX,
                    "dx": UC_X86_REG_RDX,
                    "di": UC_X86_REG_RDI,
                    "si": UC_X86_REG_RSI,
                    "bp": UC_X86_REG_RBP,
                    "sp": UC_X86_REG_RSP}

        self.mu.mem_map(self.text_base, 0x10000)
        self.mu.mem_map(self.stack_base, self.stack_size)

    def print_code_and_registers(self, mu, address, size, user_data):
        red = "\u001b[31;1m"
        green = "\u001b[32;1m"
        normal = "\u001b[0m"

        inst = mu.mem_read(address, size)
        for dis in self.md.disasm(inst, size):
            if self.show_output:
                print("")
                for reg_name, reg in self.regs.items():
                    if reg_name in self.relevant_registers:
                        reg_value = mu.reg_read(reg)
                        print("{:s} = 0x{:<16x}".format(reg_name, reg_value), end="")

                print("\n" + "0x{:<16x}\t".format(address),
                        red + "{:x}\t".format(int.from_bytes(mu.mem_read(address, size), byteorder='little')),
                        green,
                        dis.mnemonic,
                        dis.op_str,
                        normal)
            if dis.mnemonic.startswith("int"):
                mu.reg_write(self.regs["ip"], address + size)


    def print_code(self, mu, address, size, user_data):
        red = "\u001b[31;1m"
        green = "\u001b[32;1m"
        normal = "\u001b[0m"

        inst = mu.mem_read(address, size)

        for dis in self.md.disasm(inst, size):
            if self.show_output:
                print("\n" + "0x{:<16x}\t".format(address),
                        red + "{:x}\t".format(int.from_bytes(mu.mem_read(address, size), byteorder='little')),
                        green,
                        dis.mnemonic,
                        dis.op_str,
                        normal)
            if dis.mnemonic.startswith("int"):
                mu.reg_write(self.regs["ip"], address + size)


    def run(self, code, hook_fn=None, relevant_registers=None):
        self.mu.mem_write(self.text_base, code)
        self.mu.reg_write(self.regs["sp"], self.stack_base + self.stack_size)

        if hook_fn == None:
            hook_fn = self.print_code_and_registers
        elif hook_fn not in self.hooks:
            hook_fn = functools.partial(hook_fn, self)

        if relevant_registers == None:
            self.relevant_registers = self.regs.keys()
        else:
            self.relevant_registers = relevant_registers


        self.mu.hook_add(UC_HOOK_CODE, hook_fn)
        if self.show_output:
            print("[+] - Starting emulation")
        self.mu.emu_start(self.text_base, len(code))

        esp = self.mu.reg_read(self.regs["sp"])
        stack_contents = bytes(self.mu.mem_read(esp, self.stack_base + self.stack_size - esp))
        if self.show_output and len(stack_contents) > 0:
            print("STACK <{} bytes>: ".format(len(stack_contents)))
            hexdump(stack_contents)

        return self.mu
