#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
    int checksum_old = packet[11]*0x100 + packet[10];
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
    checksum += checksum_old;
    packet[10] = packet10;
    packet[11] = packet11;
    return (checksum == 0xffff );
}
