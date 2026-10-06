# Lab1：链路层学习骨架

实际开发目录：`my-lab:~/labs/netstack-lab/lab1/`。
配件目录：`~/labs/lab-netstack-premium/`。本地 lab1 是初始骨架副本，之后以远程修改为准。

采用 C11 + libpcap + Makefile。`list` 已实现；PT1/PT2 核心函数保留 TODO，
未实现函数返回 -1 并设置 errno=ENOSYS，不会假装收发成功。

## 构建及入口

```bash
ssh my-lab
cd ~/labs/netstack-lab/lab1
make
./build/lab1_demo list
```

服务器依赖：build-essential、libpcap-dev、tcpdump、iproute2。
网卡枚举也可能显示 any、lo 等设备；注册时必须检查链路类型为 DLT_EN10MB，
不要把所有枚举项都当成可用的 Ethernet II 设备。

## 实现顺序

1. **PT1 设备表**：在 device.c 内管理设备数组；ID 对应表项。
   先写 findDevice，再写 addDevice：校验名称、查重、读 MAC/MTU、打开 pcap、
   检查数据链路类型，全部成功后才注册。失败时关闭临时句柄。
   起步可用 pcap_open_live；用 getifaddrs 或 ioctl 读硬件地址。
2. **PT2 发送**：按 `目的 MAC(6) | 源 MAC(6) | EtherType(2) | 数据` 组帧。
   接口传入主机字节序 EtherType，写入帧时 htons；收到时 ntohs。
   检查负长度、空指针、无效 ID、MTU；不足 60 字节补零，不包含 FCS，不计算 CRC。
   调用 pcap_inject，并检查返回值是否等于整个帧长。
3. **PT2 接收**：先完成单网卡阻塞接收。pcap_next_ex 得到完整帧后调用已注册回调，
   传递设备 ID 和实际捕获长度；区分超时、错误及结束，丢弃短帧/截断帧。
   回调拿到的 pcap 内存不能在下一次读取后继续使用，需要保留时复制。
4. **CP1/CP2**：先枚举网卡，再在两个 namespace 间发帧，用接收打印与 tcpdump 交叉检查。
5. **WT1**：独立用 Wireshark 分析给定 trace.pcap，填写 docs/report.md。

初期所有接口按单线程使用设计。以后接入多网卡及 Lab2 时，再明确接收调度、
每个 pcap 句柄的所有权和共享设备表同步；不要直接让多个线程同时操作同一句柄。

## 双主机演示（完成 TODO 后）

拓扑文件与配套 vnetUtils 格式一致，创建 l1ns1/l1ns2，接口为
l1veth1-2/l1veth2-1。下面的命令需要在服务器手动执行：

```bash
cd ~/labs/lab-netstack-premium/vnetUtils/examples
sudo bash ./makeVNet < ~/labs/netstack-lab/lab1/topology/two-hosts.txt
```

若配件 helper 提示权限错误，先给 helper 脚本添加执行权限；若提示 CRLF 则转换行尾。
在三个终端分别执行（抓包与接收先启动，最后发送）：

```bash
# 终端 A：抓包
sudo ip netns exec l1ns2 tcpdump -i l1veth2-1 -e -XX 'ether proto 0x88b5'
# 终端 B：自己的接收程序
sudo ip netns exec l1ns2 ~/labs/netstack-lab/lab1/build/lab1_demo recv l1veth2-1
# 终端 C：自己的发送程序
sudo ip netns exec l1ns1 ~/labs/netstack-lab/lab1/build/lab1_demo send l1veth1-2
```

演示固定发送广播帧，payload 为 hello from lab1，EtherType 为 0x88b5。
随后可扩展 CLI 支持单播目的 MAC。保留 checkpoints/ 下的截图、日志、pcap。
演示完成后 Ctrl-C 停止抓包/接收，再清理本次拓扑：

```bash
cd ~/labs/lab-netstack-premium/vnetUtils/examples
sudo bash ./removeVNet < ~/labs/netstack-lab/lab1/topology/two-hosts.txt
```

Lab1 自定义以太网帧演示不需要关闭宿主机内核协议栈。

## 提交结构

保留 src/、Makefile、checkpoints/；将 docs/report.md 与
docs/not-implemented.md 据实补全并导出为根目录的 README.pdf 和 not-implemented.pdf。
Markdown 模板不是最终要求的 PDF；无需提交 build/ 构建产物。
