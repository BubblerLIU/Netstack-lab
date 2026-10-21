对于lab2 IP协议设计，考虑设计生产者-消费者模型。

1. 应用启动，调用 `startIPModule` 接口
2. `startIPModule` 执行以下任务：
    1. 初始化路由表
    2. 初始化 send buffer 和 recv buffer
    3. 注册接收回调函数
    4. 启动缓冲区轮询线程，如果 recv buffer 有待消费的产物，就调用回调函数处理，如果 send buffer 有待消费的产物，就调用 `sendIPPacket` 接口发送
    5. 启动设备监听线程，如果收到目标是自己的 packet，就放入 recv buffer
3. 应用接下来可以调用 `submitSend` 接口，向 send buffer 放入发送请求
4. 应用准备关闭，调用 `stopIPModule` 释放线程和内存资源

分析这个设计是否可行，工程量是否过大。