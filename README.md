# execute-assembly
execute-assembly

写了一个符合实际使用的程序,先把要加载的EXE使用0x91异或,修改对应的数组变量和size变量
本项目实现了patch amsi和patch etw,C#程序异或，通过PIPE读取执行结果，所以超过400字节的输出会被截断，最好的办法是C#里面有--outfile参数可以定义输出。
都只测试基于.net 4以上版本的C#程序可以正常运行，比如Seatbelt,rubeus,bsk。


综合了以下优秀项目
```
https://github.com/N4kedTurtle/ExecuteAssembly_Mailslot
https://github.com/b4rtik/metasploit-execute-assembly
https://raw.githubusercontent.com/3gstudent/Homework-of-C-Language/master/HostingCLR_with_arguments_XOR_TamperETW.cpp
```

# TODO
测试加载自己写的C#程序时，回提示不能call method，待解决。
