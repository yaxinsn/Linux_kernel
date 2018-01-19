# Linux_kernel

# linux 与应用层的几种通信方式。

nf_sock_opt

genl

netlink就不测试了。

ioctl()这个需要在socket.c中增加一个入口。可以看一下SIOIWFIRST

misc file 以文件/dev/XXXX为入口。

自己写一个socket，这个难度大。
