[toc]

# fibonacci

## 查看运行效果

- [文件下载地址](http://eternal.red/assets/files/2017/UE/fibonacci)

![](https://i.loli.net/2021/09/21/tQreWYl16dVP7sp.png)

- 运行就会输出flag，但是输出速度特别慢，所以我们要解决的问题是加速它的输出速度
- 通过unicorn去优化程序

## ida 静态分析

- main 函数

```c++
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char *v3; // rbp
  int v4; // ebx
  __int64 v5; // r8
  char v6; // r9
  __int64 v7; // r8
  char v8; // cl
  int fibvar[7]; // [rsp+Ch] [rbp-1Ch] BYREF

  v3 = (char *)&unk_4007E1;
  v4 = 0;
  setbuf(stdout, 0LL);
  printf("The flag is: ");
  while ( 1 )
  {
    LODWORD(v5) = 0;
    do
    {
      fibvar[0] = 0;
      fibonacci((unsigned int)(v4 + v5), fibvar);
      v8 = v7;
      v5 = v7 + 1;
    }
    while ( v5 != 8 );
    v4 += 8;
    if ( (unsigned __int8)(fibvar[0] << v8) == v6 )
      break;
    ++v3;
    _IO_putc(v6 ^ (unsigned __int8)(LOBYTE(fibvar[0]) << v8), stdout);
  }
  _IO_putc(10, stdout);
  return 0LL;
}
```

> 1. mian函数有三个输出点
> 2. 第一个输出点输出："The flag is: "
> 3. 第二个输出点输出：flag
> 4. mian输出的flag只和fibvar[0]有关，和fibonacci函数返回值无关
> 5. 第三个输出点输出：换行符
> 6. main 函数地址：0x00000000004004E0
> 7. fibonacci函数地址：0x0000000000400670
> 8. 第三个输出点地址：0x0000000000400575

- 为什么他的Fibonacci数列计算的如此值慢，我们应该思考，并且要思考如何解决这种问题

> 1. 慢的原因在于这个fibonacci数列是通过递归调用的方式去实现的
> 2. 解决方式就是：[动态编程](https://www.hackerearth.com/practice/algorithms/dynamic-programming/introduction-to-dynamic-programming-1/tutorial/)
> 3. 动态编程的核心在于它保存了后面需要的值，而不是继续重复去计算

- 我自己写了一个通过循环去解决fibonacci递归调用问题，注释部分为ida生成作者的C语言版fibonacci，运行即可看见效率，那么我们的unicorn就应该按照这种方式去优化代码执行

```c++
// fibonacci.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
/*
__int64 fibonacci(int a1, int* a2)
{
    int v3; // er12
    __int64 result; // rax
    unsigned int v5; // esi
    unsigned int v6; // esi

    if (a1)
    {
        if (a1 == 1)
        {
            result = fibonacci(0, a2);
        }
        else
        {
            v3 = fibonacci(a1 - 2, a2);
            result = v3 + (unsigned int)fibonacci(a1 - 1, a2);
        }
        v5 = (((unsigned int)result - (((unsigned int)result >> 1) & 0x55555555)) >> 2) & 0x33333333;// C语言中，对于移位操作执行的是逻辑左移和算术右移，不过对于无符号类型，所有的移位操作都是逻辑的。
        v6 = v5
            + ((result - (((unsigned int)result >> 1) & 0x55555555)) & 0x33333333)
            + ((v5 + (((DWORD)result - (((unsigned int)result >> 1) & 0x55555555)) & 0x33333333)) >> 4);
        *a2 ^= ((BYTE(v6) & 0xF) + (v6 & 0xF) + (unsigned __int8)((((v6 >> 8) & 0xF0F0F) + (v6 & 0xF0F0F0F)) >> 16)) & 1;
    }
    else
    {
        *a2 ^= 1u;                                  // 一个10进制1异或
        result = 1LL;                               // long long int 1
    }
    return result;
}
*/
void myfibonacci(int a1)
{
    double fibvar[200] = { 0 };
    fibvar[0] = 0;
    fibvar[1] = 1;
    if (0 == a1)
    {
        std::cout << "第" << a1 << "个fibonacci : " << fibvar[a1] << "\n";
    }
    else if (1 == a1)
    {
        std::cout << "第" << a1 << "个fibonacci : " << fibvar[a1] << "\n";
    }
    else
    {
        for (size_t i = 2; i < sizeof(fibvar) / sizeof(int); i++)
        {
            fibvar[i] = fibvar[i - 1] + fibvar[i - 2];
            std::cout << "第" << i << "个fibonacci : " << fibvar[i] << "\n";
        }
        
    }
    
}

int main()
{
    myfibonacci(180);
    /*
    int fibvar[7] = {0};
    int n = 0;
    while (n < 40)
    {
        fibonacci(n, fibvar);
        std::cout << n << " fibvar : " << fibvar[0] << "\n";
        n++;
    }*/
    std::cout << "Hello World!\n";
}
```



- fibonacci

```c++
__int64 __fastcall fibonacci(int a1, _DWORD *a2)
{
  int v3; // er12
  __int64 result; // rax
  unsigned int v5; // esi
  unsigned int v6; // esi

  if ( a1 )
  {
    if ( a1 == 1 )
    {
      result = fibonacci(0, a2);
    }
    else
    {
      v3 = fibonacci(a1 - 2, a2);
      result = v3 + (unsigned int)fibonacci(a1 - 1, a2);
    }
    v5 = (((unsigned int)result - (((unsigned int)result >> 1) & 0x55555555)) >> 2) & 0x33333333;// C语言中，对于移位操作执行的是逻辑左移和算术右移，不过对于无符号类型，所有的移位操作都是逻辑的。
    v6 = v5
       + ((result - (((unsigned int)result >> 1) & 0x55555555)) & 0x33333333)
       + ((v5 + (((_DWORD)result - (((unsigned int)result >> 1) & 0x55555555)) & 0x33333333)) >> 4);
    *a2 ^= ((BYTE1(v6) & 0xF) + (v6 & 0xF) + (unsigned __int8)((((v6 >> 8) & 0xF0F0F) + (v6 & 0xF0F0F0F)) >> 16)) & 1;
  }
  else
  {
    *a2 ^= 1u;                                  // 一个10进制1异或
    result = 1LL;                               // long long int 1
  }
  return result;
}
```

> 1. 要想优化这个fibonacci函数，首先要搞清楚这个函数的参数以及返回值
> 2. a1 = ? ,a2 = ? 时，a2会被修改为多少，result =？
> 3. 我想弄明白以上问题，我就有方法绕过这糟糕的fibonacci函数了
> 4. 那么我们就保存以上四组值，当输入参数等于我们保存的a1和a2时，我们已经知道了a2被修改为多少，reslut是多少，那么我们就可以不执行递归调用了
> 5. fibonacci数列前两个值特殊处理，

```c++
v3 = fibonacci(a1 - 2, a2);
result = v3 + (unsigned int)fibonacci(a1 - 1, a2);
```

> 1. 返回值是result，通过上面的表达式我们可以看出result是通过fibonacci函数返回值累加的结果

## 解决方案

- 首先保存一个字典d(a1,a2)(result，a2)
- 在fibonacci函数调用时，验证参数是否已经在字典中
- 如果在，修改RIP值到函数结尾处，如果不在，在函数结尾处把执行的结果保存到字典中（提高了效率，绕开了递归调用）

```python
# coding=<encoding UTF-8>

from unicorn import *   # unicorn base constant
from unicorn.x86_const import * # special x86 and x64 constant
from pwn import *   
import struct


def read(name):
    '''

    '''
    #with open(name, encoding='utf-8') as f:
    with open(name, 'rb') as f:
        return f.read()

#def u32(data):
    '''
    return 4 BYTE string to integer (little)
    '''
    #return struct.unpack("I", data)[0]

#def p32(num):
    '''
    return integer to 4 BYTE string (little)
    You can install pwntools
    from pwn import *
    '''
    #return struct.pack("I", num)

instructions_skip_list = [0x00000000004004EF, 0x00000000004004F6, 0x0000000000400502, 0x000000000040054F]
FIBONACCI_ENTRY = 0x0000000000400670
FIBONACCI_END = [0x00000000004006F1, 0x0000000000400709]

stack = []                                          # Stack for storing the arguments
d = {}                                              # Dictionary that holds return values for given function arguments 

def hook_code(mu, address, size, user_data):  
    #print('>>> Tracing instruction at 0x%x, instruction size = 0x%x' %(address, size))
    
    if address in instructions_skip_list:
        mu.reg_write(UC_X86_REG_RIP, address+size)
    
    elif address == 0x0000000000400560:                       # That instruction writes a byte of the flag
        c = mu.reg_read(UC_X86_REG_RDI)
        print(chr(c))
        mu.reg_write(UC_X86_REG_RIP, address+size)
    
    elif address == FIBONACCI_ENTRY:                # Are we at the beginning of fibonacci function?
        arg0 = mu.reg_read(UC_X86_REG_RDI)          # Read the first argument. Tt is passed via RDI
        r_rsi = mu.reg_read(UC_X86_REG_RSI)         # Read the second argument which is a reference
        arg1 = u32(mu.mem_read(r_rsi, 4))           # Read the second argument from reference
        
        if (arg0,arg1) in d:                        # Check whether return values for this function are already saved.
            (ret_rax, ret_ref) = d[(arg0,arg1)]
            mu.reg_write(UC_X86_REG_RAX, ret_rax)   # Set return value in RAX register
            mu.mem_write(r_rsi, p32(ret_ref))       # Set retun value through reference
            mu.reg_write(UC_X86_REG_RIP, 0x400582)  # Set RIP to point at RET instruction. We want to return from fibonacci function
            
        else:
            stack.append((arg0,arg1,r_rsi))         # If return values are not saved for these arguments, add them to stack.
        
    elif address in FIBONACCI_END:
        (arg0, arg1, r_rsi) = stack.pop()           # We know arguments when exiting the function
        
        ret_rax = mu.reg_read(UC_X86_REG_RAX)       # Read the return value that is stored in RAX
        ret_ref = u32(mu.mem_read(r_rsi,4))         # Read the return value that is passed reference
        d[(arg0, arg1)]=(ret_rax, ret_ref)          # Remember the return values for this argument pair


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
mu.hook_add(UC_HOOK_CODE, hook_code)
mu.emu_start(0x00000000004004E0,0x0000000000400575)

```

