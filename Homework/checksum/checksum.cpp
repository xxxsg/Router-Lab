#include <stdint.h>
#include <stdlib.h>
#include <iostream>
using namespace std;

/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
	// TODO:
	uint32_t Checksum = 0;
	uint16_t p10 = packet[10], p11 = packet[11];
	size_t tmp_len = packet[0]&0xf;
  size_t IHL = tmp_len;
  tmp_len*=4;
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
	packet -= IHL*4;
	packet[10] = p10;
	packet[11] = p11;
	/*for (int i = 0; i < IHL*4; i++)
		cout << hex << (uint16_t)packet[i] << " ";
	cout << endl;
	cout << hex << p10 << " " << p11 << " " << ans1 << " " << ans2 << " " << ~ans1 << " " << ~ans2 << endl;*/
	return flag;
}