#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <utility>
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
uint16_t get_checksum(uint8_t *packet, size_t len){
    int packet10 = packet[10];
    int packet11 = packet[11];
    packet[10] = 0;
    packet[11] = 0;
    int checksum = 0;
    //分组相加
    int head_len = packet[0] % 0x10 * 4;
    int arry[head_len/2+1];
    for(int i = 0; i < head_len/2; i++){
        arry[i] = 0;
    }
    for(int i = 0; i < head_len; i++){
        i%2 == 1 ? arry[i/2] += packet[i] * 0x100 : arry[i/2] += packet[i];
    }
    //处理溢出
    for(int i = 0; i < head_len/2; i++){
        checksum += arry[i]; 
    }
    while(checksum > 0xffff){
        int temp = checksum / 0x10000;
        checksum %= 0x10000;
        checksum += temp;
    }
    packet[10] = packet10;
    packet[11] = packet11;
    return 0xffff-checksum;
}

bool forward(uint8_t *packet, size_t len) {
    //printf("%02x\n", packet[8]);
    uint16_t checksum_old = packet[11]*0x100 + packet[10];
	if(get_checksum(packet, len) != checksum_old) return false;
    //TTL减1
    packet[8] -= 1;
    uint16_t checksum = get_checksum(packet, len);
    packet[11] = checksum / 0x100;
    packet[10] = checksum % 0x100;
    return true;
}
