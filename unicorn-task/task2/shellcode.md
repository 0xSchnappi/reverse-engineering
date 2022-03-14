[toc]

# shellcode

## shellcode disasm

```python
from pwn import *

shellcode = b'\xe8\xff\xff\xff\xff\xc0\x5d\x6a\x05\x5b\x29\xdd\x83\xc5\x4e\x89\xe9\x6a\x02\x03\x0c\x24\x5b\x31\xd2\x66\xba\x12\x00\x8b\x39\xc1\xe7\x10\xc1\xef\x10\x81\xe9\xfe\xff\xff\xff\x8b\x45\x00\xc1\xe0\x10\xc1\xe8\x10\x89\xc3\x09\xfb\x21\xf8\xf7\xd0\x21\xd8\x66\x89\x45\x00\x83\xc5\x02\x4a\x85\xd2\x0f\x85\xcf\xff\xff\xff\xec\x37\x75\x5d\x7a\x05\x28\xed\x24\xed\x24\xed\x0b\x88\x7f\xeb\x50\x98\x38\xf9\x5c\x96\x2b\x96\x70\xfe\xc6\xff\xc6\xff\x9f\x32\x1f\x58\x1e\x00\xd3\x80'

print(disasm(shellcode))
```

- windows 下运行不起，具体原因还没探究，我用的是kali python3

![](https://i.loli.net/2021/09/22/OLxYal5PnMoquy6.png)

## unicorn inital step

1. 定义内存大小，比如代码区、堆栈空间
2. Uc获取对应架构实例
3. mem_map内存映射（分配内存）
4. mem_write在映射的内存空间中写入要执行的代码，初始化寄存器的状态
