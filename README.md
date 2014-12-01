OpenVPN-Linux-kernel
====================

在内核处理OpenVPN数据通道
控制通道依然在OpenVPN本身进行处理，数据通道被移植进了Linux内核。
增加了几个tun的ioctl命令，用来：
1.将一个UDP socket和tun连接起来，用于数据通道的短路操作；
2.添加multi_instance进内核；
3.为multi_instance增加一个虚拟地址；
4.为一个multi_instance设置密钥；
...
TODO
