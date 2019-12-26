#include "rip.h"
#include<iostream>
#include <stdint.h>
#include <stdlib.h>
using namespace std;
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
 uint32_t BigToSmallEndien2(uint32_t x)
{
	return ((x & 0xff000000) >> 24) | ((x & 0x00ff0000) >> 8) | ((x & 0x0000ff00) << 8) | ((x & 0x000000ff) << 24);
}
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
	// TODO:
	// for (int i = 0; i < len; i++)
		// cout << hex << (uint16_t)packet[i] << " ";
   	// cout<<endl;
	uint32_t total_length = packet[2],header_length=(packet[0]&0xf)*4;
	total_length <<= 8;
	total_length += packet[3];
   	// cout<<len<<" "<<total_length<<" "<<header_length<<endl;
	if (total_length > len)
		return false;
	uint16_t command = packet[header_length + 8];
	 //cout<<command<<endl;
	if(!((command==1)||(command==2)))
		return false;
	uint16_t version = packet[header_length + 9];
	// cout<<version<<endl;
	if(version!=2)
		return false;
	uint16_t zero_1 = packet[header_length + 10];
	uint16_t zero_2 = packet[header_length + 11];
	if(zero_1!=0||zero_2!=0)
		return false;

	if((total_length-header_length-12)%20!=0)
		return false;

	output->numEntries =(total_length-header_length-12)/20 ;
	output->command=command;
	for(int i=0;i<output->numEntries;i++)
	{
		uint32_t family = packet[header_length + 12];
		family <<= 8;
		family+= packet[header_length + 13];
		// cout<<"family:"<<family<<endl;
		if(command==1&&family!=0)
			return false;
		if(command==2&&family!=2)
			return false;

		uint16_t tag_1 = packet[header_length + 14];
		uint16_t tag_2 = packet[header_length + 15];
		uint32_t ipaddr = packet[header_length + 19];
		ipaddr <<= 8;
		ipaddr += packet[header_length + 18];
		ipaddr <<= 8;
		ipaddr += packet[header_length + 17];
		ipaddr <<= 8;
		ipaddr += packet[header_length + 16];

		uint32_t mask = packet[header_length + 23];
		mask <<= 8;
		mask += packet[header_length + 22];
		mask <<= 8;
		mask += packet[header_length + 21];
		mask <<= 8;
		mask += packet[header_length + 20];
		int flag=1;

//cout<<hex<<"mask:"<<mask<<"ipaddr:"<<ipaddr<<endl;
uint32_t tmpmask=BigToSmallEndien2(mask);
// uint32_t tmpmask = mask;
		for(int j=31;j>=0;j--)
//		for (int j = 0; j <= 31; j++)
		{
			int tmp=tmpmask&(1u<<j);
			if(tmp)
				tmp=1;
			// cout<<tmp;
			if(!tmp)
				flag=0;
			if(tmp!=flag)
				return false;
		}
		// cout<<endl;
		

		uint32_t nexthop = packet[header_length + 27];
		nexthop <<= 8;
		nexthop += packet[header_length + 26];
		nexthop <<= 8;
		nexthop += packet[header_length + 25];
		nexthop <<= 8;
		nexthop += packet[header_length + 24];

		uint32_t metric = packet[header_length + 31];
		metric <<= 8;
		metric += packet[header_length + 30];
		metric <<= 8;
		metric += packet[header_length + 29];
		metric <<= 8;
		metric += packet[header_length + 28];
		int realmetric=metric;
		realmetric>>=24;
		 //cout<<"metric:"<<realmetric<<endl;
		if(realmetric<1||realmetric>16)
			return false;

		output->entries[i].addr=ipaddr;
		output->entries[i].mask=mask;
		output->entries[i].nexthop=nexthop;
		output->entries[i].metric=metric;
		header_length+=20;
		// cout<<hex<<ipaddr<<" "<<mask<<" "<<nexthop<<" "<<metric<<endl;

	}


	//cout << total_length << endl;
	//cout << hex << total_length;
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
	// TODO:
	buffer[0]=rip->command;
	buffer[1]=2;
	buffer[2]=buffer[3]=0;
	// int offset=0;
	buffer-=20;
	for(int i=0;i<rip->numEntries;i++)
	{
		buffer+=20;
		// offset=i*20;
		buffer[4]=0;
		if(rip->command==2)
			buffer[5]=2;
		else 
			buffer[5]=0;
		buffer[6]=buffer[7]=0;
		int ipaddr=rip->entries[i].addr;
		buffer[8]=ipaddr&0xff;
		ipaddr>>=8;
		buffer[9]=ipaddr&0xff;
		ipaddr>>=8;
		buffer[10]=ipaddr&0xff;
		ipaddr>>=8;
		buffer[11]=ipaddr&0xff;
		int mask=rip->entries[i].mask;
		buffer[12]=mask&0xff;
		mask>>=8;
		buffer[13]=mask&0xff;
		mask>>=8;
		buffer[14]=mask&0xff;
		mask>>=8;
		buffer[15]=mask&0xff;
		int nexthop=rip->entries[i].nexthop;
		buffer[16]=nexthop&0xff;
		nexthop>>=8;
		buffer[17]=nexthop&0xff;
		nexthop>>=8;
		buffer[18]=nexthop&0xff;
		nexthop>>=8;
		buffer[19]=nexthop&0xff;
		int metric=rip->entries[i].metric;
		buffer[20]=metric&0xff;
		metric>>=8;
		buffer[21]=metric&0xff;
		metric>>=8;
		buffer[22]=metric&0xff;
		metric>>=8;
		buffer[23]=metric&0xff;
	}
	return 4+20*rip->numEntries;
	return 0;
}
