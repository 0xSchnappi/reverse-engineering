from unicorn import *
from unicorn.x86_const import *


import struct

def read(name):
    with open(name, 'rb') as f:
        return f.read()
        
def u32(data):
    return struct.unpack("I", data)[0]
    
def p32(num):
    return struct.pack("I", num)


mu = Uc (UC_ARCH_X86, UC_MODE_64)


BASE = 0x400000
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024

mu.mem_map(BASE, 1024*1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)


mu.mem_write(BASE, read("./fibonacci"))
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE - 1)

instructions_skip_list = [0x00000000004004EF, 0x00000000004004F6, 0x0000000000400502, 0x000000000040054F]

def hook_code(mu, address, size, user_data):  
    #print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
    
    if address in instructions_skip_list:
        mu.reg_write(UC_X86_REG_RIP, address+size)
    
    elif address == 0x400560: #that instruction writes a byte of the flag
        c = mu.reg_read(UC_X86_REG_RDI)
        print(chr(c))
        mu.reg_write(UC_X86_REG_RIP, address+size)

mu.hook_add(UC_HOOK_CODE, hook_code)



mu.emu_start(0x00000000004004E0, 0x0000000000400575)
