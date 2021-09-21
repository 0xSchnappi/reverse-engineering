[toc]

# Acid burn.exe

## 运行

![](https://i.loli.net/2021/09/21/dIVM5zs9rbgoJut.png)

- 使用的是MessageBox函数的弹框
- 如果用C++调用一般为

```C++
#include <windows.h>

MessageBox(NULL, "Welcome to this Newbies Crackme made by ACID BuRN [CrackerWoRID]","hello you have to kill me!",MB_OK);
```

## 解决方法

### 方案一

- 通过字符串搜索找到调用MessageBox函数处

  ![](https://i.loli.net/2021/09/21/NmTbktMEFHfLXp7.png)

  ![](https://i.loli.net/2021/09/21/KkWMvmXJnygihVj.png)

  ![](https://i.loli.net/2021/09/21/tUnoaq7HNkQg8mB.png)

- 在0x0042A1A9 行汇编代码处 ctrl+9 ，然后点击确定

  ![](https://i.loli.net/2021/09/21/x2iy9wEfW3K6RAp.png)

- ctrl + p 点击修补文件（完毕）

  ![](https://i.loli.net/2021/09/21/vPV4cRpbIsj7LUC.png)

### 方案二

- 通过对MessageBox函数下断点，然后通过栈回溯找到调用者

![](https://i.loli.net/2021/09/22/YaV8ZjdHenRruXS.png)

- 0x0042a1a9 就是MessageBox调用处，用90机器码替换掉这里的机器码保存即可
