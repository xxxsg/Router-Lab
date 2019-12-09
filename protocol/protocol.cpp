#include "rip.h"
#include <stdint.h>
#include <stdlib.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
    int total_len = packet[3];
    //Total Length 大于 len 时，把传入的 IP 包视为不合法
    if(total_len > len) return false;
    int iphead_len = (packet[0] & 0xf) * 4; 
    int command, version, zero[2], family, tag[2], metric, mask, addr, nexthop;
    //检查 Command 是否为 1 或 2
    command = iphead_len+8;
    if(packet[command] != 1 && packet[command] != 2) return false;
    //Version 是否为 2
    version = iphead_len+8+1;
    if(packet[version] != 2) return false;
    // Zero 是否为 0
    zero[0] = iphead_len+8+2;
    zero[1] = iphead_len+8+3;
    if(packet[zero[0]] || packet[zero[1]]) return false;    
    //推断包的个数
    int packet_num = (total_len - iphead_len- 8) / 20;
    output->numEntries = packet_num;
    output->command = packet[command];
    for(int i  = 0; i < packet_num; i++){
      int pzero = zero[1] + i * 20 + 1;
      //Family 和 Command 是否有正确的对应关系
      family = pzero;
      int family_value = (packet[family] << 8) + packet[family+1];
      if(!((packet[command] == 1 && family_value == 0) || (packet[command] == 2 && family_value == 2))) return false;
      //Tag 是否为 0
      tag[0] = pzero + 2;
      tag[1] = pzero + 3;
      if(packet[tag[0]] || packet[tag[1]]) return false;
      //addr;
      addr = pzero + 4;      
      output->entries[i].addr = (packet[addr+3] << 24) + (packet[addr+2] << 16) + (packet[addr+1] << 8) +packet[addr];
      //Mask 的二进制是不是连续的 1 与连续的 0 组成等等    
      mask = pzero + 8;
      uint32_t mask_value = (packet[mask+3] << 24) + (packet[mask+2] << 16) + (packet[mask+1] << 8) +packet[mask+0];
      if((1 != __builtin_popcount((mask_value) + 1))) return false;
      output->entries[i].mask = mask_value;
      //nexthop;
      nexthop = pzero + 12;
      output->entries[i].nexthop = (packet[nexthop+3] << 24) + (packet[nexthop+1] << 16) + (packet[nexthop+1] << 8) +packet[nexthop];
      //Metric 转换成小端序后是否在 [1,16] 的区间内
      metric = pzero + 16;
      uint32_t metric_velue = (packet[metric] << 24) + (packet[metric+1] << 16) + (packet[metric+2] << 8) +packet[metric+3];
      if(metric_velue < 1 || metric_velue > 16) return false;
      output->entries[i].metric = (packet[metric+3] << 24) + (packet[metric+2] << 16) + (packet[metric+1] << 8) +packet[metric];
    }
    return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
    buffer[0] = rip->command;
    buffer[1] = 2;
    buffer[2] = buffer[3] = 0;
    for(int i = 0; i < rip->numEntries; i++){
      int zero = 4 + i * 20;
      buffer[zero] = 0;
      if (rip->command == 2) buffer[zero + 1] = 2;
      else if(rip->command == 1) buffer[zero + 1] = 0;
      buffer[zero + 2] = buffer[zero + 3] = 0;
      //addr
      uint32_t temp;
      temp = rip->entries[i].addr;
      for (int j = 0; j < 4; j++){
        buffer[zero+4+j] = (temp & 0xff);
        temp = temp >> 8;
      }
      //mask
      temp = rip->entries[i].mask;
      for (int j = 0; j < 4; j++){
        buffer[zero+8+j] = (temp & 0xff);
        temp = temp >> 8;
      }      
      //nexthop
      temp = rip->entries[i].nexthop;
      for (int j = 0; j < 4; j++){
        buffer[zero+12+j] = (temp & 0xff);
        temp = temp >> 8;
      }  
      //metric
      temp = rip->entries[i].metric;
      for (int j = 0; j < 4; j++){
        buffer[zero+16+j] = (temp & 0xff);
        temp = temp >> 8;
      }  
    }
    // TODO:
    return rip->numEntries * 20 + 4;
}
