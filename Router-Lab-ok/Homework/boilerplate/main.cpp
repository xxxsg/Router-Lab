#include "rip.h"
#include "router.h"
#include "router_hal.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
using namespace std;

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index, uint32_t *metric);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);

extern uint16_t get_checksum(uint8_t *packet, size_t len);
extern vector<RoutingTableEntry> routingtable;

uint8_t packet[2048];
uint8_t output[2048];


//my code function
extern uint32_t get_mask(uint32_t len);
extern uint32_t get_netaddr(RoutingTableEntry now);
void deal_output(int i, RipPacket rip);//add 1 3 7 9

uint32_t big_to_small(uint32_t x){
	uint32_t x1 = (x & 0xff000000) >> 24;
	uint32_t x2 = (x & 0x00ff0000) >> 8;
	uint32_t x3 = (x & 0x0000ff00) << 8;
	uint32_t x4 = (x & 0x000000ff) << 24;
	return (x1 | x2 | x3 | x4);
}

// 0: 192.168.3.2
// 1: 192.168.4.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = { 0x0203a8c0, 0x0104a8c0, 0x0102000a,0x0103000a };


int main(int argc, char *argv[]) {
	// 0a.
	int res = HAL_Init(1, addrs);
	if (res < 0) {
		return res;
	}

	// 0b. Add direct routes
	// For example:
	// 10.0.0.0/24 if 0
	// 10.0.1.0/24 if 1
	// 10.0.2.0/24 if 2
	// 10.0.3.0/24 if 3
	for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++) {
		RoutingTableEntry entry = {
			.addr = addrs[i], // big endian
			.len = 24,        // small endian
			.if_index = i,    // small endian
			.nexthop = 0,      // big endian, means direct
			.metric = big_to_small(1u)
		};
		update(true, entry);
		printf("addrs[%u] : %x\n", i, addrs[i]);
	}


	////--Add Here 1-- 
	for (int i = 0; i < N_IFACE_ON_BOARD; i++) {
		RipPacket rip;
		rip.command = 1;
		rip.numEntries = 1;
		rip.entries[0].addr = 0;
		rip.entries[0].mask = 0;
		rip.entries[0].metric = big_to_small(16u);
		rip.entries[0].nexthop = 0;
		deal_output(i, rip);
		uint32_t rip_l = assemble(&rip, &output[20 + 8]);
		macaddr_t dst_mac;
		if (HAL_ArpGetMacAddress(i, 0x090000e0, dst_mac) == 0)
			HAL_SendIPPacket(i, output, rip_l + 20 + 8, dst_mac);
		else
			printf("WRONG! DST_MAC NOT FOUND!");
	}
	////--Add Here 1-- 
	

	uint64_t last_time = 0;
	while (1)
	{
		for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++)
		{
			RoutingTableEntry entry = {
				.addr = addrs[i], // big endian
				.len = 24,        // small endian
				.if_index = i,    // small endian
				.nexthop = 0,      // big endian, means direct
				.metric = big_to_small(1u)
			};
			update(true, entry);
			//printf("addrs[%u] = %x\n", i, addrs[i]);
		}
		uint64_t time = HAL_GetTicks();
		if (time > last_time + 5 * 1000)
		{
			// What to do?
			// send complete routing table to every interface
			// ref. RFC2453 3.8
			//TODO:split horizon
			//responce
			// multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
			//--Add Here 2--
			printf("\nTimer response routingtable:\n");
			for (int i = 0; i < routingtable.size(); i++){
				RoutingTableEntry t = routingtable[i];
				printf("addr: %x, len: %u, if_index: %u, nexthop: %x, metric: %u\n", t.addr, t.len, t.if_index, t.nexthop, big_to_small(t.metric));
			}

			for (int i = 0; i < N_IFACE_ON_BOARD; i++){
				RipPacket rip;
				rip.command = 2;
				rip.numEntries = 0;
				for (int j = 0; j < routingtable.size(); j++){
					if ((addrs[i] & get_mask(routingtable[j].len)) == (routingtable[j].addr&get_mask(routingtable[j].len)))
						continue;
					if (routingtable[j].nexthop == addrs[i])
						continue;
					if (routingtable[j].if_index == i)
						continue;
					rip.entries[rip.numEntries].addr = routingtable[j].addr&get_mask(routingtable[j].len);
					rip.entries[rip.numEntries].mask = get_mask(routingtable[j].len);
					rip.entries[rip.numEntries].metric = routingtable[j].metric;
					rip.entries[rip.numEntries].nexthop = routingtable[j].nexthop;
					rip.numEntries++;
				}
				deal_output(i, rip);
				uint32_t rip_len = assemble(&rip, &output[20 + 8]);
				macaddr_t dst_mac;
				if (HAL_ArpGetMacAddress(i, 0x090000e0, dst_mac) == 0) {
					HAL_SendIPPacket(i, output, rip_len + 20 + 8, dst_mac);
					//printf("timer response!!!\n");
				}
				else
					printf("WRONG! DST_MAC NOT FOUND!");
				//MAC?????TODO
			}
			//--Add Here 2--

			printf("\nTimer : 5s \n\n");
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
		in_addr_t src_addr = 0;
		in_addr_t dst_addr = 0;
		in_addr_t mc_addr = 0x090000E0;
		// extract src_addr and dst_addr from packet
		// big endian
		//--Add Here 3--
		//src
		src_addr += packet[15];
		src_addr <<= 8;
		src_addr += packet[14];
		src_addr <<= 8;
		src_addr += packet[13];
		src_addr <<= 8;
		src_addr += packet[12];
		//dst
		dst_addr += packet[19];
		dst_addr <<= 8;
		dst_addr += packet[18];
		dst_addr <<= 8;
		dst_addr += packet[17];
		dst_addr <<= 8;
		dst_addr += packet[16];
		//--Add Here 3--
		// 2. check whether dst is me
		bool dst_is_me = false;
		for (int i = 0; i < N_IFACE_ON_BOARD; i++)
		{
			if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0)
			{
				dst_is_me = true;
				break;
			}
			//--Add Here 4--
			if (memcmp(&dst_addr, &mc_addr, sizeof(in_addr_t)) == 0) {
				dst_is_me = true;
				break;
			}
			//--Add Here 4--
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
					printf("handing request....\n");
					//检验是否为请求报文，判断度量值是否为16，地址族标识是否为0；
					//--Add Here 5--
					if (rip.numEntries != 1){
						printf("ERROR! numEntries not 1\n");
						continue;
					}
					if (big_to_small(rip.entries[0].metric) != 16){
						printf("ERROR! metric is not 16\n");
						continue;
					}
					//--Add Here 5--

					// 3a.3 request, ref. RFC2453 3.9.1
					// only need to respond to whole table requests in the lab
					// 封装和源ip地址不在同一网段

					//--Add Here 6--
					RipPacket resp;
					resp.command = 2;
					resp.numEntries = 0;
					for (int i = 0; i < routingtable.size(); i++){
						if (get_netaddr(routingtable[i]) == (src_addr&get_mask(routingtable[i].len))){
							if (routingtable[i].if_index == if_index)
								continue;
							resp.entries[resp.numEntries].addr = routingtable[i].addr&get_mask(routingtable[i].len);
							resp.entries[resp.numEntries].mask = get_mask(routingtable[i].len);
							resp.entries[resp.numEntries].nexthop = routingtable[i].nexthop;
							resp.entries[resp.numEntries].metric = routingtable[i].metric;//应该是几？？？TODO
							resp.numEntries++;
						}
					}
					printf("routingtable:\n");
					for (int i = 0; i < routingtable.size(); i++){
						RoutingTableEntry tmp = routingtable[i];
						printf("addr: %x , len: %u , if_index: %u , nexthop: %x , metric: %u\n", tmp.addr, tmp.len, tmp.if_index, tmp.nexthop, big_to_small(tmp.metric));
					}
					//--Add Here 6--

					// TODO: fill resp
					// assemble
					//--Add Here 7--
					// IP
					output[0] = 0x45;
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
					uint16_t checksum = get_checksum(output, totlen);
					output[10] = checksum & 0xff;
					output[11] = ((checksum & 0xff00) >> 8);
					//--Add Here 7--
					// UDP
					// port = 520
					output[20] = 0x02;
					output[21] = 0x08;//src port
					//--Add Here 8--
					output[22] = 0x02;
					output[23] = 0x08;//dst port
					//24-25 len
					totlen -= 20;
					output[24] = totlen / 0x100;
					output[25] = totlen % 0x100;
					//26-27 validation
					output[26] = output[27] = 0;
					//--Add Here 8--

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
				else
				{
					// 3a.2 response, ref. RFC2453 3.9.2


					//--Add Here 9--
					printf("\nhandling response:\n");
					bool updated = false;
					for (int i = 0; i < rip.numEntries; i++){
						uint32_t curMetric = rip.entries[i].metric;
						uint32_t addr = rip.entries[i].addr;
						uint32_t mask = rip.entries[i].mask;
						uint32_t len = __builtin_popcount(mask);
						uint32_t nexthop = rip.entries[i].nexthop;
						if (nexthop == 0){
							nexthop = src_addr;
						}
						curMetric = big_to_small(curMetric);
						curMetric = min(curMetric + 1, 16u);
						//查路由表
						bool found = false;
						for (int j = 0; j < routingtable.size(); j++)
							if (len == routingtable[j].len){
								if (get_netaddr(routingtable[j]) == (get_mask(len)&addr)){
									found = true;
									if (curMetric >= 16&&nexthop==routingtable[j].nexthop){
										RoutingTableEntry del_tmp;
										del_tmp.addr=addr;
										del_tmp.len = len;
										update(false, del_tmp);
										printf("deleting Route\n");
										break;
									}
									if (curMetric <= big_to_small(routingtable[j].metric)){
										//update
										updated = true;
										routingtable[j].addr = addr;
										routingtable[j].metric = big_to_small(curMetric);
										routingtable[j].nexthop = nexthop;
										routingtable[j].if_index = if_index;
										printf("updated routing complite\n");
										//TODO:what is if_index?
									}
									break;
								}
							}
						if (!found&&curMetric<16){
							updated = true;
							RoutingTableEntry tmp;
							tmp.addr = addr;
							tmp.len = len;
							tmp.metric = big_to_small(curMetric);
							tmp.if_index = if_index;
							tmp.nexthop = src_addr;
							update(true, tmp);
							printf("not found! adding new Routing!\n");
						}

					}
					for (uint32_t i = 0; i < N_IFACE_ON_BOARD; i++){
						RoutingTableEntry entry = {
							.addr = addrs[i], // big endian
							.len = 24,        // small endian
							.if_index = i,    // small endian
							.nexthop = 0,      // big endian, means direct
							.metric = big_to_small(1u)
						};
						update(true, entry);
						//printf("addrs[%u] = %x\n", i, addrs[i]);
					}
					if (updated){
						printf("routingtable updated:\n");
						for (int k = 0; k < N_IFACE_ON_BOARD; k++){
							RipPacket rip;
							rip.command = 2;
							rip.numEntries = 0;
							for (int i = 0; i < routingtable.size(); i++){
								if ((addrs[k] & get_mask(routingtable[i].len)) == (routingtable[i].addr&get_mask(routingtable[i].len)))
									continue;
								if (routingtable[i].nexthop == addrs[k])
									continue;
								if (routingtable[i].if_index == k)
									continue;
								rip.entries[rip.numEntries].addr = routingtable[i].addr&get_mask(routingtable[i].len);
								rip.entries[rip.numEntries].mask = get_mask(routingtable[i].len);
								rip.entries[rip.numEntries].metric = routingtable[i].metric;
								rip.entries[rip.numEntries].nexthop = routingtable[i].nexthop;
								rip.numEntries++;
							}
							deal_output(k, rip);
							uint32_t rip_len = assemble(&rip, &output[20 + 8]);
							macaddr_t dst_mac;
							if (HAL_ArpGetMacAddress(k, 0x090000e0, dst_mac) == 0){
								HAL_SendIPPacket(k, output, rip_len + 20 + 8, dst_mac);
								printf("update response complite\n");
							}
							else
								printf("WRONG! DST_MAC NOT FOUND!");
							//MAC?????TODO
						}
					}
					printf("\nroutingtable:\n");
					for (int i = 0; i < routingtable.size(); i++){
						RoutingTableEntry t = routingtable[i];
						printf("Addr:%x  Len:%u  If_index:%u  Nexthop:%x  Metric:%u\n", t.addr, t.len, t.if_index, t.nexthop, big_to_small(t.metric));
					}

					//--Add Here 9--


					// update routing table
					// new metric = ?
					// update metric, if_index, nexthop
					// what is missing from RoutingTableEntry?
					// TODO: use query and update
					// triggered updates? ref. RFC2453 3.10.1
				}
			}
			else
				printf("ERROR! DURING DISASSEMBLE VALIDATION!\n");
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
				printf("Dest_if = %u, Nexthop = %x\n", dest_if, nexthop);
				if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0)
				{
					// found
					memcpy(output, packet, res);
					// update ttl and checksum
					// TODO: you might want to check ttl=0 case
					//--Add Here 10--
					bool ok = forward(output, res);
					if (!ok){
						printf("ERROR! checksum wrong or TTL = 0");
						continue;
					}
					else{
						printf("FORWARDING PACKET!\n");
						HAL_SendIPPacket(dest_if, output, res, dest_mac);
					}
					//--Add Here 10--
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
				printf("IP not found for %x\n", src_addr);
			}
		}
	}
	return 0;
}


//mycode add 1
void deal_output(int i, RipPacket rip){
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
	output[12] = addrs[i] & 0xff;
	output[13] = (addrs[i] >> 8) & 0xff;
	output[14] = (addrs[i] >> 16) & 0xff;
	output[15] = (addrs[i] >> 24) & 0xff;
	//printf("output : %x %x %x %x\n", output[12], output[13], output[14], output[15]);
	//printf("ok: %x\n", addrs[i]);
	//16-19 dst ip
	output[16] = 0xe0;
	output[17] = 0x00;
	output[18] = 0x00;
	output[19] = 0x09;
	//10-11 validation
	uint16_t checksum = get_checksum(output, totlen);
	output[10] = checksum & 0xff;
	output[11] = ((checksum & 0xff00) >> 8);
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
	return;
}
