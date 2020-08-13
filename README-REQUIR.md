## Router

arp -a

pi

ssh pi@192.168.137.

raspberry

vncserver -geometry 1280x1024

vncserver -geometry 1920x1080

192.168.137.



```c++
int main() {
    // 0a. 初始化 HAL，打开调试信息
    HAL_Init(1, addrs);
    // 0b. 创建若干条 /24 直连路由
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
        RoutingTableEntry entry = {
            .addr = addrs[i] & 0x00FFFFFF, // big endian
            .len = 24,
            .if_index = i,
            .nexthop = 0 // means direct
        };
        update(true, entry);
    }

    uint64_t last_time = 0;
    while (1) {
        // 获取当前时间，处理定时任务
        uint64_t time = HAL_GetTicks();
        if (time > last_time + 30 * 1000) {
            // 每 30s 做什么
            // 例如：超时？发 RIP Request/Response？
            last_time = time;
        }

        // 轮询
        int mask = (1 << N_IFACE_ON_BOARD) - 1;
        macaddr_t src_mac;
        macaddr_t dst_mac;
        int if_index;
        int res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                                    dst_mac, 1000, &if_index); // 超时为 1s
        if (res > 0) {
            // 1. 检查是否是合法的 IP 包，可以用你编写的 validateIPChecksum 函数，还需要一些额外的检查
            // 2. 检查目的地址，如果是路由器自己的 IP（或者是 RIP 的组播地址），进入 3a；否则进入 3b
            // 3a.1 检查是否是合法的 RIP 包，可以用你编写的 disassemble 函数检查并从中提取出数据
            // 3a.2 如果是 Response 包，就调用你编写的 query 和 update 函数进行查询和更新，
            //      注意此时的 RoutingTableEntry 可能要添加新的字段（如metric、timestamp），
            //      如果有路由更新的情况，可能需要构造出 RipPacket 结构体，调用你编写的 assemble 函数，
            //      再把 IP 和 UDP 头补充在前面，通过 HAL_SendIPPacket 把它发到别的网口上
            // 3a.3 如果是 Request 包，就遍历本地的路由表，构造出一个 RipPacket 结构体，
            //      然后调用你编写的 assemble 函数，另外再把 IP 和 UDP 头补充在前面，
            //      通过 HAL_SendIPPacket 发回询问的网口
            // 3b.1 此时目的 IP 地址不是路由器本身，则调用你编写的 query 函数查询，
            //      如果查到目的地址，如果是直连路由， nexthop 改为目的 IP 地址，
            //      用 HAL_ArpGetMacAddress 获取 nexthop 的 MAC 地址，如果找到了，
            //      就调用你编写的 forward 函数进行 TTL 和 Checksum 的更新，
            //      通过 HAL_SendIPPacket 发到指定的网口，
            //      在 TTL 减到 0 的时候建议构造一个 ICMP Time Exceeded 返回给发送者；
            //      如果没查到目的地址的路由，建议返回一个 ICMP Destination Network Unreachable；
            //      如果没查到下一跳的 MAC 地址，HAL 会自动发出 ARP 请求，在对方回复后，下次转发时就知道了
        } else if (res == 0) {
            // Timeout, ignore
        } else {
            fprintf(stderr, "Error: %d\n", res);
            break;
        }
    }
    return 0;
}
```

![image-20191212141332369](C:\Users\82331\AppData\Roaming\Typora\typora-user-images\image-20191212141332369.png)

- PC1 是否与 PC2 能够正常通信：使用 `ping` 测试 ICMP、`curl` 测试 TCP 连接
- R2 的转发是否通过 HAL 完成，而非 Linux 自带的路由转发功能：在 R2 上使用 `ip a` 命令确认连接 R1 和 R3 的网口上没有配置 IP 地址
- R1、R3 上的 RIP 路由表是否正确：包括 RIP metric 等信息，从 R1 和 R3 上 运行的 BIRD 输出得到
- R2 向 R1、R3 发出的 RIP 协议报文是否正确：包括是否响应了请求，以及是否实现了水平分裂（split horizon）算法，在 R1 和 R3 上用 Wireshark 抓包检查
- R2 上的 RIP 路由表、转发表是否正确：需要你定期或者每次收到报文时打印最新的 RIP 路由表、系统转发表（见 FAQ 中对于路由表和转发表的讨论），格式自定，可以模仿 `ip route` 的输出格式