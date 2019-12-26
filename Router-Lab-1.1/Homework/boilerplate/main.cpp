#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
using namespace std;

extern vector<RoutingTableEntry> RoutingTable;
extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern pair<bool, uint16_t> validateIPChecksum1(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

extern uint32_t Mask(uint32_t len);

extern uint32_t Netaddr(RoutingTableEntry now);

uint32_t BigToSmallEndien(uint32_t x)
{
	return ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) | ((x & 0x000000ff) << 24);
}

uint8_t packet[2048];
uint8_t output[2048];
// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = { 0x0204a8c0, 0x0205a8c0, 0x0102000a, 0x0103000a };

int main(int argc, char *argv[])
{
	// 0a.
	int res = HAL_Init(1, addrs);
	if (res < 0)
	{
		return res;
	}

	// 0b. Add direct routes
	// For example:
	// 10.0.0.0/24 if 0
	// 10.0.1.0/24 if 1
	// 10.0.2.0/24 if 2
	// 10.0.3.0/24 if 3
	for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++)
	{
		RoutingTableEntry entry = {
			.addr = addrs[i], // big endian
			.len = 24,        // small endian
			.if_index = i,    // small endian
			.nexthop = 0,      // big endian, means direct
			.metric = BigToSmallEndien(1u)
		};
		update(true, entry);
		//printf("addrs[%u] = %x\n", i, addrs[i]);
	}

	//MY CODE START.................................................................................................
	for (int k = 0; k < N_IFACE_ON_BOARD; k++)
	{
		RipPacket rip;
		rip.command = 1;
		rip.numEntries = 1;
		rip.entries[0].addr = 0;
		rip.entries[0].mask = 0;
		rip.entries[0].metric = BigToSmallEndien(16u);
		rip.entries[0].nexthop = 0;
		output[0] = 0x45;
		output[1] = 0x00;//TOS
		//2-3 total len
		uint32_t totlen = 20 + 8 + 4 + rip.numEntries * 20;
		output[2] = totlen / 0x100;
		output[3] = totlen % 0x100;
		output[4] = output[5] = 0x00;//ID
		output[6] = output[7] = 0x00;//OFF
		output[8] = 0x01;//TTL
		output[9] = 0x11;//UDP
		//12-15 src ip
		output[12] = addrs[k] & 0xff;
		output[13] = (addrs[k] >> 8) & 0xff;
		output[14] = (addrs[k] >> 16) & 0xff;
		output[15] = (addrs[k] >> 24) & 0xff;
		//printf("%x %x %x %x\n", output[12], output[13], output[14], output[15]);
		//printf("%x\n", addrs[k]);
		//16-19 dst ip
		output[16] = 0xe0;
		output[17] = 0x00;
		output[18] = 0x00;
		output[19] = 0x09;
		//10-11 validation
		pair<bool, uint16_t> tmp = validateIPChecksum1(output, totlen);
		output[10] = tmp.second & 0xff;
		output[11] = ((tmp.second & 0xff00) >> 8);
		// ...
		// UDP
		// port = 520
		output[20] = 0x02;
		output[21] = 0x08;//src port
		output[22] = 0x02;
		output[23] = 0x08;//dst port
		//24-25 len
		totlen -= 20;
		output[24] = totlen / 0x100;
		output[25] = totlen % 0x100;
		//26-27 validation
		output[26] = output[27] = 0;
		uint32_t rip_len = assemble(&rip, &output[20 + 8]);
		macaddr_t dst_mac;
		if (HAL_ArpGetMacAddress(k, 0x090000e0, dst_mac) == 0)
			HAL_SendIPPacket(k, output, rip_len + 20 + 8, dst_mac);
		else
			printf("WRONG! DST_MAC NOT FOUND!");
	}
	//MY CODE END.................................................................................................





	uint64_t last_time = 0;
	while (1)
	{
		uint64_t time = HAL_GetTicks();
		if (time > last_time + 5 * 1000)
		{
			// What to do?
			// send complete routing table to every interface
			// ref. RFC2453 3.8
			//MY CODE START.................................................................................................
			//TODO:split horizon
			//responce
			// multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
			printf("Timer response RoutingTable: size: %d\n", RoutingTable.size());
			for (int i = 0; i < RoutingTable.size(); i++)
			{
				RoutingTableEntry tmp = RoutingTable[i];
				// printf("addr: %x , len: %u , if_index: %u , nexthop: %x , metric: %u\n", tmp.addr, tmp.len, tmp.if_index, tmp.nexthop, BigToSmallEndien(tmp.metric));
			}

			for (int k = 0; k < N_IFACE_ON_BOARD; k++)
			{
				//printf("sending if_index:%d\n",k);
				bool stoprip = false;
				int lst = 0;
				while (!stoprip)
				{
					RipPacket rip;
					rip.command = 2;
					rip.numEntries = 0;
					for (int i = lst; i < RoutingTable.size(); i++)
					{
						if (i == RoutingTable.size() - 1)
							stoprip = true;
						if (RoutingTable[i].if_index == k)
							continue;
						else
						{
							//printf("split horizon addr:%x if_index: %u\n",RoutingTable[i].addr,k);
							rip.entries[rip.numEntries].addr = RoutingTable[i].addr&Mask(RoutingTable[i].len);
							rip.entries[rip.numEntries].mask = Mask(RoutingTable[i].len);
							rip.entries[rip.numEntries].metric = RoutingTable[i].metric;
							rip.entries[rip.numEntries].nexthop = RoutingTable[i].nexthop;
							rip.numEntries++;
							if (rip.numEntries == 25)
							{
								lst = i + 1;
								break;
							}
						}
					}
					output[0] = 0x45;
					output[1] = 0x00;//TOS
					//2-3 total len
					uint32_t totlen = 20 + 8 + 4 + rip.numEntries * 20;
					output[2] = totlen / 0x100;
					output[3] = totlen % 0x100;
					output[4] = output[5] = 0x00;//ID
					output[6] = output[7] = 0x00;//OFF
					output[8] = 0x01;//TTL
					output[9] = 0x11;//UDP
					//12-15 src ip
					output[12] = addrs[k] & 0xff;
					output[13] = (addrs[k] >> 8) & 0xff;
					output[14] = (addrs[k] >> 16) & 0xff;
					output[15] = (addrs[k] >> 24) & 0xff;
					//16-19 dst ip
					output[16] = 0xe0;
					output[17] = 0x00;
					output[18] = 0x00;
					output[19] = 0x09;
					//10-11 validation
					pair<bool, uint16_t> tmp = validateIPChecksum1(output, totlen);
					output[10] = tmp.second & 0xff;
					output[11] = ((tmp.second & 0xff00) >> 8);
					// ...
					// UDP
					// port = 520
					output[20] = 0x02;
					output[21] = 0x08;//src port
					output[22] = 0x02;
					output[23] = 0x08;//dst port
					//24-25 len
					totlen -= 20;
					output[24] = totlen / 0x100;
					output[25] = totlen % 0x100;
					//26-27 validation
					output[26] = output[27] = 0;
					uint32_t rip_len = assemble(&rip, &output[20 + 8]);
					macaddr_t dst_mac;
					if (HAL_ArpGetMacAddress(k, 0x090000e0, dst_mac) == 0)
					{
						HAL_SendIPPacket(k, output, rip_len + 20 + 8, dst_mac);
						//printf("timer response!!!\n");
					}
					else
						printf("WRONG! DST_MAC NOT FOUND!");
					//MAC?????TODO
				}
			}

			//MY CODE END.................................................................................................
			printf("5s Timer\n");
			last_time = time;
		}

		int mask = (1 << N_IFACE_ON_BOARD) - 1;
		macaddr_t src_mac;
		macaddr_t dst_mac;
		int if_index;
		res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac, dst_mac,
			1000, &if_index);
		if (res == HAL_ERR_EOF)
		{
			printf("HAL_ERR_EOF\n");
			break;
		}
		else if (res < 0)
		{
			printf("res<0\n");
			return res;
		}
		else if (res == 0)
		{
			// Timeout
			//printf("timeout!\n");
			continue;
		}
		else if (res > sizeof(packet))
		{
			printf("truncated!\n");
			// packet is truncated, ignore it
			continue;
		}


		// 1. validate
		if (!validateIPChecksum(packet, res))
		{
			printf("Invalid IP Checksum\n");
			continue;
		}
		in_addr_t src_addr, dst_addr, mc_addr;
		// extract src_addr and dst_addr from packet
		// big endian
		//MY CODE START.................................................................................................

		//printf("Packet:");
		//for (int i = 0; i < res; i++)
		//	printf("%x ", packet[i]);
		src_addr = 0;
		src_addr += packet[15];
		src_addr <<= 8;
		src_addr += packet[14];
		src_addr <<= 8;
		src_addr += packet[13];
		src_addr <<= 8;
		src_addr += packet[12];

		dst_addr = 0;
		dst_addr += packet[19];
		dst_addr <<= 8;
		dst_addr += packet[18];
		dst_addr <<= 8;
		dst_addr += packet[17];
		dst_addr <<= 8;
		dst_addr += packet[16];

		mc_addr = 0x090000E0;

		//MY CODE END.................................................................................................
		// 2. check whether dst is me
		bool dst_is_me = false;
		for (int i = 0; i < N_IFACE_ON_BOARD; i++)
		{
			if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0)
			{
				dst_is_me = true;
				break;
			}
			//MY CODE START.................................................................................................
			if (memcmp(&dst_addr, &mc_addr, sizeof(in_addr_t)) == 0)
			{
				dst_is_me = true;
				break;
			}
			//MY CODE END.................................................................................................
		}
		// TODO: Handle rip multicast address(224.0.0.9)?
		//printf("src: %x \ndst: %x \nif_index: %d\n", src_addr, dst_addr, if_index);
		if (dst_is_me)
		{
			// 3a.1
			RipPacket rip;
			// check and validate
			if (disassemble(packet, res, &rip))
			{
				if (rip.command == 1)
				{
					//printf("handing request....\n");
					//检验是否为请求报文，判断度量值是否为16，地址族标识是否为0；
					//MY CODE START.................................................................................................
					if (rip.numEntries != 1)
					{
						printf("ERROR! numEntries not 1\n");
						continue;
					}
					if (BigToSmallEndien(rip.entries[0].metric) != 16)
					{
						printf("ERROR! metric is not 16\n");
						continue;
					}
					//MY CODE END.................................................................................................
					// 3a.3 request, ref. RFC2453 3.9.1
					// only need to respond to whole table requests in the lab
					// 封装和源ip地址不在同一网段
					//MYCODE START .................................................................................................
					bool stoprip = false;
					int lst = 0;
					while (!stoprip)
					{
						RipPacket resp;
						resp.command = 2;
						resp.numEntries = 0;
						for (int i = lst; i < RoutingTable.size(); i++)
						{
							if (i == RoutingTable.size() - 1)
								stoprip = true;
							if (Netaddr(RoutingTable[i]) != (src_addr&Mask(RoutingTable[i].len)))//!@#@@!#@!@#TODO ----BUG
							{
								if (RoutingTable[i].if_index == if_index)
									continue;
								resp.entries[resp.numEntries].addr = RoutingTable[i].addr&Mask(RoutingTable[i].len);
								resp.entries[resp.numEntries].mask = Mask(RoutingTable[i].len);
								resp.entries[resp.numEntries].nexthop = RoutingTable[i].nexthop;
								resp.entries[resp.numEntries].metric = RoutingTable[i].metric;//应该是几？？？TODO
								resp.numEntries++;
								if (resp.numEntries == 25)
								{
									lst = i + 1;
									break;
								}
							}
						}
						//printf("RoutingTable:\n");
						//for (int i = 0; i < RoutingTable.size(); i++)
						//{
						//	RoutingTableEntry tmp = RoutingTable[i];
						//	printf("addr: %x , len: %u , if_index: %u , nexthop: %x , metric: %u\n", tmp.addr, tmp.len, tmp.if_index, tmp.nexthop, BigToSmallEndien(tmp.metric));
						//}
						//MY CODE END.................................................................................................
						// TODO: fill resp
						// assemble
						// IP
						output[0] = 0x45;
						//MY CODE START.................................................................................................
						output[1] = 0x00;//TOS
						//2-3 total len
						uint32_t totlen = 20 + 8 + 4 + resp.numEntries * 20;
						output[2] = totlen / 0x100;
						output[3] = totlen % 0x100;
						output[4] = output[5] = 0x00;//ID
						output[6] = output[7] = 0x00;//OFF
						output[8] = 0x01;//TTL
						output[9] = 0x11;//UDP
						//12-15 src ip
						uint32_t recv_addr = addrs[if_index];
						output[12] = recv_addr & 0xff;
						output[13] = (recv_addr >> 8) & 0xff;
						output[14] = (recv_addr >> 16) & 0xff;
						output[15] = (recv_addr >> 24) & 0xff;
						//16-19 dst ip
						output[16] = src_addr & 0xff;
						output[17] = (src_addr >> 8) & 0xff;
						output[18] = (src_addr >> 16) & 0xff;
						output[19] = (src_addr >> 24) & 0xff;
						//10-11 validation
						pair<bool, uint16_t> tmp = validateIPChecksum1(output, totlen);
						output[10] = tmp.second & 0xff;
						output[11] = ((tmp.second & 0xff00) >> 8);
						//MY CODE END.................................................................................................
						// ...
						// UDP
						// port = 520
						output[20] = 0x02;
						output[21] = 0x08;//src port
						//MYCODE START.................................................................................................
						output[22] = 0x02;
						output[23] = 0x08;//dst port
						//24-25 len
						totlen -= 20;
						output[24] = totlen / 0x100;
						output[25] = totlen % 0x100;
						//26-27 validation
						output[26] = output[27] = 0;

						//MYCODE END.................................................................................................
						// ...
						// RIP
						//MODIFIED!!! &rip->&resp
						uint32_t rip_len = assemble(&resp, &output[20 + 8]);
						//MODIFIED!!!
						// checksum calculation for ip and udp
						// if you don't want to calculate udp checksum, set it to zero
						// send it back
						HAL_SendIPPacket(if_index, output, rip_len + 20 + 8, src_mac);
					}
				}
				else
				{
					// 3a.2 response, ref. RFC2453 3.9.2
					//MY CODE START.....................................................................
					//printf("handling response...from %x\n",src_addr);
					bool updated = false;
					for (int i = 0; i < rip.numEntries; i++)
					{
						uint32_t curMetric = rip.entries[i].metric;
						uint32_t addr = rip.entries[i].addr;
						uint32_t mask = rip.entries[i].mask;
						uint32_t len = __builtin_popcount(mask);
						uint32_t nexthop = rip.entries[i].nexthop;
						//printf("rip %d: addr: %x len: %u metric: %u nexthop: %x\n",i,addr,len,BigToSmallEndien(curMetric),nexthop);
						if (nexthop == 0)
						{
							nexthop = src_addr;
						}
						curMetric = BigToSmallEndien(curMetric);
						curMetric = min(curMetric + 1, 16u);
						//查路由表
						bool found = false;
						for (int j = 0; j < RoutingTable.size(); j++)
							if (len == RoutingTable[j].len)
							{
								if (Netaddr(RoutingTable[j]) == (Mask(len)&addr))
								{
									found = true;
									if (curMetric >= 16 && nexthop == RoutingTable[j].nexthop)
									{
										RoutingTableEntry del_tmp;
										del_tmp.addr = addr;
										del_tmp.len = len;
										update(false, del_tmp);
										//printf("deleting Route\n");
										break;
									}
									if (curMetric < BigToSmallEndien(RoutingTable[j].metric))
									{
										//update
										updated = true;
										RoutingTable[j].addr = addr;
										RoutingTable[j].metric = BigToSmallEndien(curMetric);
										RoutingTable[j].nexthop = nexthop;
										RoutingTable[j].if_index = if_index;
										//printf("updated routing!\n");
										//TODO:what is if_index?
									}
									break;
								}
							}
						if (!found&&curMetric < 16)
						{
							updated = true;
							RoutingTableEntry tmp;
							tmp.addr = addr;
							tmp.len = len;
							tmp.metric = BigToSmallEndien(curMetric);
							tmp.if_index = if_index;
							tmp.nexthop = src_addr;
							//printf("tmp.addr=%x\n",tmp.addr);
							update(true, tmp);
							//printf("not found! adding new Routing!\n");
						}

					}

					//printf("RoutingTable:\n");
					//for (int i = 0; i < RoutingTable.size(); i++)
					//{
					//	RoutingTableEntry tmp = RoutingTable[i];
					//	printf("addr: %x , len: %u , if_index: %u , nexthop: %x , metric: %u\n", tmp.addr, tmp.len, tmp.if_index, tmp.nexthop, BigToSmallEndien(tmp.metric));
					//}

					if (updated)
					{
						// printf("RoutingTable updated!\n");
						for (int k = 0; k < N_IFACE_ON_BOARD; k++)
						{
							bool stoprip = false;
							int lst = 0;
							while (!stoprip)
							{
								RipPacket rip;
								rip.command = 2;
								rip.numEntries = 0;
								for (int i = lst; i < RoutingTable.size(); i++)
								{
									if (i == RoutingTable.size() - 1)
										stoprip = true;
									if (RoutingTable[i].if_index == k)
										continue;
									//printf("response:%d\n",i);
									rip.entries[rip.numEntries].addr = RoutingTable[i].addr&Mask(RoutingTable[i].len);
									rip.entries[rip.numEntries].mask = Mask(RoutingTable[i].len);
									rip.entries[rip.numEntries].metric = RoutingTable[i].metric;
									rip.entries[rip.numEntries].nexthop = RoutingTable[i].nexthop;
									rip.numEntries++;
									if (rip.numEntries == 25)
									{
										lst = i + 1;
										break;
									}
								}
								output[0] = 0x45;
								output[1] = 0x00;//TOS
								//2-3 total len
								uint32_t totlen = 20 + 8 + 4 + rip.numEntries * 20;
								output[2] = totlen / 0x100;
								output[3] = totlen % 0x100;
								output[4] = output[5] = 0x00;//ID
								output[6] = output[7] = 0x00;//OFF
								output[8] = 0x01;//TTL
								output[9] = 0x11;//UDP
								//12-15 src ip
								output[12] = addrs[k] & 0xff;
								output[13] = (addrs[k] >> 8) & 0xff;
								output[14] = (addrs[k] >> 16) & 0xff;
								output[15] = (addrs[k] >> 24) & 0xff;
								//16-19 dst ip
								output[16] = 0xe0;
								output[17] = 0x00;
								output[18] = 0x00;
								output[19] = 0x09;
								//10-11 validation
								pair<bool, uint16_t> tmp = validateIPChecksum1(output, totlen);
								output[10] = tmp.second & 0xff;
								output[11] = ((tmp.second & 0xff00) >> 8);
								// ...
								// UDP
								// port = 520
								output[20] = 0x02;
								output[21] = 0x08;//src port
								output[22] = 0x02;
								output[23] = 0x08;//dst port
								//24-25 len
								totlen -= 20;
								output[24] = totlen / 0x100;
								output[25] = totlen % 0x100;
								//26-27 validation
								output[26] = output[27] = 0;
								uint32_t rip_len = assemble(&rip, &output[20 + 8]);
								macaddr_t dst_mac;
								if (HAL_ArpGetMacAddress(k, 0x090000e0, dst_mac) == 0)
								{
									HAL_SendIPPacket(k, output, rip_len + 20 + 8, dst_mac);
									//printf("update response!!!\n");
								}
								else
									printf("WRONG! DST_MAC NOT FOUND!");
							}
							//MAC?????TODO
						}
					}
					//printf("RoutingTable:\n");
					//for (int i = 0; i < RoutingTable.size(); i++)
					//{
					//	RoutingTableEntry tmp = RoutingTable[i];
					//	printf("addr: %x , len: %u , if_index: %u , nexthop: %x , metric: %u\n", tmp.addr, tmp.len, tmp.if_index, tmp.nexthop, BigToSmallEndien(tmp.metric));
					//}

					//MY CODE END.....................................................................

					// update routing table
					// new metric = ?
					// update metric, if_index, nexthop
					// what is missing from RoutingTableEntry?
					// TODO: use query and update
					// triggered updates? ref. RFC2453 3.10.1
				}
			}
			else
			{
				
			printf("ERROR! DURING DISASSEMBLE VALIDATION!\naddr=%x,if_index=%u,dst_addr=%x\n", src_addr, if_index, dst_addr);
				
				/*printf("details:\n");
				for (int i = 0; i < res; i++)
				{
					printf("%x ", packet[i]);
				}
				printf("\n");
				*/
			}
		}
		else
		{
			printf("SHOULD FORWARD!\n");
				// 3b.1 dst is not me
				// forward
				// beware of endianness
			uint32_t nexthop, dest_if, metric;
			if (query(dst_addr, &nexthop, &dest_if, &metric))
			{
				// found
				macaddr_t dest_mac;
				// direct routing
				if (nexthop == 0)
				{
					nexthop = dst_addr;
				}
				printf("dest_if = %u, nexthop = %x, dst_ip:%x\n", dest_if, nexthop, dst_addr);
				if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0)
				{
					// found
					memcpy(output, packet, res);
					// update ttl and checksum
					// TODO: you might want to check ttl=0 case
					//MY CODE START.......................................................................
					bool ok = forward(output, res);
					if (!ok)
					{
						printf("ERROR! checksum wrong or TTL = 0");
						continue;
					}
					else
					{
						printf("FORWARDING PACKET!\n");
						HAL_SendIPPacket(dest_if, output, res, dest_mac);
					}
					//MY CODE END.....................................................................
				}
				else
				{
					// not found
					// you can drop it
					printf("ARP not found for %x\n", nexthop);
				}
			}
			else
			{
				// not found
				// optionally you can send ICMP Host Unreachable
				printf("IP not found from %x for %x \n", src_addr, dst_addr);
			}
		}
	}
	return 0;
}
