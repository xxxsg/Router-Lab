#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <vector>
#include <iostream>
using namespace std;

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

/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 *
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 */
vector<RoutingTableEntry> RoutingTable;
uint32_t BigToSmallEndien1(uint32_t x)
{
	return ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) | ((x & 0x000000ff) << 24);
}

uint32_t Mask(uint32_t len)
{
	if (len == 0)
		return 0;
	return BigToSmallEndien1(~((1 << (32 - len)) - 1));
	// return (1 << len) - 1;
}

uint32_t Netaddr(RoutingTableEntry now)
{
	return Mask(now.len) & now.addr;
}

void update(bool insert, RoutingTableEntry entry) {
	// TODO:
	if (insert)
	{
		for (int i = 0; i < RoutingTable.size(); i++)
		{
			if (RoutingTable[i].len == entry.len&&(RoutingTable[i].addr&Mask(entry.len)) == (entry.addr&Mask(entry.len)))
			{
				RoutingTable[i] = entry;
				return;
			}
		}
		RoutingTable.push_back(entry);
	}
	else
	{
		for (int i = 0; i < RoutingTable.size(); i++)
			if (RoutingTable[i].len == entry.len && (RoutingTable[i].addr&Mask(entry.len)) == (entry.addr&Mask(entry.len)))
			{
				RoutingTable.erase(RoutingTable.begin() + i);
				return;
			}
	}
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric) {
	// TODO:
	*nexthop = 0;
	*if_index = 0;
	uint32_t id = -1;
	for (int i = 0; i < RoutingTable.size(); i++)
	{
		RoutingTableEntry now = RoutingTable[i];
		uint32_t netAddr = Netaddr(now);
		if (netAddr == (addr&Mask(now.len)))
		{
			if (id == -1)
				id = i;
			else if (now.len > RoutingTable[id].len)
				id = i;
		}
	}
	if (id == -1)
		return false;
	*nexthop = RoutingTable[id].nexthop;
	*if_index = RoutingTable[id].if_index;
	*metric = RoutingTable[id].metric;
	return true;
}
