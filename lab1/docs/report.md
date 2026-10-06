# Lab1 报告草稿

## WT1

用 Wireshark 打开配件目录的 pcap-trace/trace.pcap，设置显示过滤器：
`eth.src == 6a:15:0a:ba:9b:7c`，选过滤结果中的第三帧。

1. 过滤后帧数：827。
2. 第三帧的目的 MAC 及特殊含义：ff:ff:ff:ff:ff:ff。
3. 第三帧从 0 开始的字节偏移 71（十六进制 0x47）的值：0x15。

## PT1 / PT2 代码安排

- src/device.c：网卡枚举、注册、查询及资源释放。
- src/packetio.c：以太网帧封装、注入、接收及回调。
- src/apps/lab1_demo.c：CP1/CP2 演示入口。

## CP1

TODO：附网卡枚举输出、截图及说明，材料放 checkpoints/。

## CP2

TODO：附双主机拓扑、命令、收发输出、tcpdump 抓包及字段解释。
核对目的 MAC、源 MAC、EtherType 和 payload。

## 实现与边界情况

TODO：设备重复注册、无效 ID、错误回滚、超 MTU、短帧、截断抓包、字节序。

提交前将完整报告导出为 lab1/README.pdf。
