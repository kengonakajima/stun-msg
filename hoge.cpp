#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "include/stun/msg.h"

void dumpbin(const char*s, size_t l) {
    for(size_t i=0;i<l;i++){
        fprintf(stderr, "%02x ", s[i] & 0xff );
        if((i%8)==7) fprintf(stderr,"  ");
        if((i%16)==15) fprintf(stderr,"\n");
    }
    fprintf(stderr,"\n");
}


int main(int argc, char* argv[]) {
    if(argc!=2) {
        printf("arg: server_ip\n");
        return 1;
    }


    struct sockaddr_in origsi;
    memset((char *) &origsi, 0, sizeof(origsi));
    origsi.sin_family = AF_INET;
    int r=inet_aton("0.0.0.0", &origsi.sin_addr);
    assert(r==1);
    origsi.sin_port = 0;

    
    struct sockaddr_in destsi; 
    memset((char *) &destsi, 0, sizeof(destsi));
    destsi.sin_family = AF_INET;
    r=inet_aton(argv[1], &destsi.sin_addr);
    assert(r==1);
    destsi.sin_port = htons(3478);

    int s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(s>0);
    r=bind(s,(struct sockaddr*)&origsi,sizeof(origsi));
    if(r<0) {
        fprintf(stderr,"bind error: %s\n",strerror(errno));
        return 1;
    }

    size_t buf_len=200;
    char buf[buf_len];
    const uint8_t tsx_id[12]={0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08, 0x09,0x0a,0x0b,0x0c };
    stun_msg_hdr *msg_hdr = (stun_msg_hdr*)buf;
    stun_msg_hdr_init(msg_hdr, STUN_BINDING_REQUEST, tsx_id);

    /*
      hdr_initだけするとこう (20b)
      00 01 (binding request)
      00 00 (cookie)
      21 12 a4 42   01 02 03 04 05 06 07 08 09 0a 0b 0c (txid)
      
     */

    stun_attr_uint32_add(msg_hdr,STUN_ATTR_CHANGE_REQUEST,0x00000000);

    /*
      これ追加すると28になって、wiresharkで見たのとおなじ
      00 01
      00 08
      21 12 a4 42   01 02 03 04 05 06 07 08 09 0a 0b 0c
      00 03 attr type  change-request
      00 04 attr len
      00 00 00 00 attr value (no change)
      
     */
    

    int l = stun_msg_len(msg_hdr);
    fprintf(stderr, "stun_msg_len:%d\n",l);    
    dumpbin(buf,l);
    
    
    // 最初のメッセージをstunサーバに送る
    r=sendto(s, buf, l, 0, (struct sockaddr*)(&destsi), sizeof(destsi));
    if(r<0) {
        fprintf(stderr,"sendto error: %s\n",strerror(errno));
        return 1;
    }

    // レスポンスを受信
    struct sockaddr_in recvsi;
    socklen_t slen=sizeof(recvsi);
    r=recvfrom(s, &buf, sizeof(buf), 0, (struct sockaddr*)(&recvsi), &slen);
    printf("recvfrom:%d from %s:%d\n", r, inet_ntoa(recvsi.sin_addr), ntohs(recvsi.sin_port));
    if(r<0) {
        fprintf(stderr,"recvfrom error: %s\n",strerror(errno));
        return 1;
    }
    const stun_attr_hdr *attr_hdr=NULL;

    if(!stun_msg_verify(msg_hdr,r)) {
        fprintf(stderr,"invalid stun message\n");
        return 1;
    }
    
    close(s);
    return 0;
}



