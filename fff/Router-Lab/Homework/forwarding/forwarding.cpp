#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include<utility>
using namespace std;
/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
pair<bool, uint16_t> validateIPChecksum1(uint8_t *packet, size_t len) {
	// TODO:
	uint32_t Checksum = 0;
	uint16_t p10 = packet[10], p11 = packet[11];
	size_t tmp_len = packet[0] & 0xf;
	size_t IHL = tmp_len;
	tmp_len *= 4;
	packet[10] = packet[11] = 0;
	while (tmp_len > 1)
	{
		Checksum += *(uint16_t *)packet;
		while (Checksum >> 16)
			Checksum = (Checksum >> 16) + (Checksum & 0xffff);
		tmp_len -= 2;
		packet++;
		packet++;
	}
	bool flag = true;
	uint16_t p1011 = (p10)+(p11 << 8);
	uint16_t ans1 = p1011, ans2 = Checksum;
	ans2 = ~ans2;
	if (ans1 != ans2)
		flag = false;
	packet -= IHL * 4;
	packet[10] = p10;
	packet[11] = p11;
	/*for (int i = 0; i < IHL*4; i++)
		cout << hex << (uint16_t)packet[i] << " ";
	cout << endl;
	cout << hex << p10 << " " << p11 << " " << ans1 << " " << ans2 << " " << ~ans1 << " " << ~ans2 << endl;*/
	//cout <<hex<< ans2 << endl;
	return pair<bool, uint16_t>{flag, ans2};
}

bool forward(uint8_t *packet, size_t len) {
	// TODO:
	if (validateIPChecksum1(packet, len).first)
	{
		packet[8] --;
		pair<bool, uint16_t> tmp = validateIPChecksum1(packet, len);
		packet[10] = tmp.second & 0xff;
		packet[11] = ((tmp.second & 0xff00) >> 8);
		//cout<<hex << tmp.second << " " << (tmp.second & 0xff) << " " << (tmp.second & 0xff00) << endl;
		return true;
	}
	else
		return false;
}
