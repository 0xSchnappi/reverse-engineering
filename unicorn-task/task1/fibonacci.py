from unicorn import *   # unicorn base constant
from unicorn.x86_const import * # special x86 and x64 cons
from pwd import *
import struct

def read(name):
    '''

    '''
    with open(name) as f:
        return f.read()

def u32(data):
    '''
    return 4 BYTE string to integer (little)
    '''
    return struct.unpack("I", data)[0]

def p32(num):
    '''
    return integer to 4 BYTE string (little)
    You can install pwntools
    from pwd import *
    '''
    return struct.pack("I", num)

mu = Uc(UC_ARCH_X86, UC_MODE_64) # inital unicorn engine 
'''
parameter 1 Architecture type
parameter 2 Architecture detail
'''

BASE = 0x400000
STACK_ADDR = 0x0
STACK_SIZE = 1024*1024

mu.mem_map(BASE, 1024*1024)
mu.mem_map(STACK_ADDR, STACK_SIZE)
'''
Image of base 0x400000
stack start 0x0
stack size 1024*1024
'''

mu.mem_write(BASE, read("./fibonacci"))
mu.reg_write(UC_X86_REG_RSP, STACK_ADDR + STACK_SIZE -1)
'''
need set rsp pointer bottom
'''

'''
now, you can start
'''

