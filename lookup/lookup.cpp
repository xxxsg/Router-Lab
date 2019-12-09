#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

RoutingTableEntry routingtable[1024];
int cnt = 0;
/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
    if(insert){
        bool routingexist = false;
        for (int i = 0; i < cnt; i++){
            if (routingtable[i].addr == entry.addr && routingtable[i].len == entry.len){
                routingexist = true;
                routingtable[i] = entry;
                break;
            }
        }
        //不存在与插入相同的表项，则在最后加
        if(!routingexist){
            routingtable[cnt++] = entry; 
        }
    }else{
        int flag = -1;
        //找到要删除的表象
        for (int i = 0; i < cnt; i++){
            if (routingtable[i].addr == entry.addr && routingtable[i].len == entry.len){
                flag = i;
                break;
            }
        }
        //没找到直接返回
        if(flag == -1) return;
        for(int i = flag; i < cnt; i++){
            routingtable[i] = routingtable[i+1];
        }
        cnt--;
    }
    //printf("routingtable:\n" ); for(int i = 0; i < cnt; i++) printf("%d: %02x %d\n",i,routingtable[i].addr,routingtable[i].len);
    return;
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool matchaddr(uint32_t addr, uint32_t addr_, int len);

bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
    int l_max = 0;
    int index = -1;
    //去匹配最长的
    for(int i = 0; i < cnt; i++){
        //如果有比当前匹配更精准的，那么去匹配
        if(routingtable[i].len > l_max){
            if(matchaddr(addr, routingtable[i].addr, routingtable[i].len)){
                l_max = routingtable[i].len;
                index = i;
            }
        }
    }
    if(index > -1){
        *nexthop = routingtable[index].nexthop;
        *if_index = routingtable[index].if_index;
        return true;
    }else{
        *nexthop = 0;
        *if_index = 0;
        return false;
    }
}

bool matchaddr(uint32_t addr, uint32_t addr_, int len){
    //printf("beginmatch: len: %d\n", len);
    for(int i = 0; i < len/8; i++){
        //printf("%d: len:%d addr:%02x addr_:%02x \n", i,len/4, addr& 0xf,addr_& 0xf);
        if((addr & 0xff) == (addr_ & 0xff)){
            addr = addr >> 8;
            addr_  = addr_ >> 8;
        }else{
            return false;
        }
    }
    len = len % 8;
    if(len > 0){
        addr = addr & 0xff;
        addr_ = addr_ & 0xff;
        addr = addr >> (8 - len);
        addr_ = addr_ >> (8 - len);
        return addr == addr_;
    }
    return true;
}