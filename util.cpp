#include "util.h"

void dumpbin(const char*s, size_t l) {
    for(size_t i=0;i<l;i++){
        fprintf(stderr, "%02x ", s[i] & 0xff );
        if((i%8)==7) fprintf(stderr,"  ");
        if((i%16)==15) fprintf(stderr,"\n");
    }
    fprintf(stderr,"\n");
}

void set_addrset(char *buf, ClientAddressSet *addrset) {
    size_t ofs=0;
    set_u32(buf+ofs, addrset->id); ofs+=4;    
    set_u32(buf+ofs, addrset->sendersa.sin_addr.s_addr); ofs+=4;
    set_u16(buf+ofs, addrset->sendersa.sin_port); ofs+=2; // nwbo
    set_u32(buf+ofs, addrset->stun0sa.sin_addr.s_addr); ofs+=4;
    set_u16(buf+ofs, addrset->stun0sa.sin_port); ofs+=2;  // nwbo
    set_u32(buf+ofs, addrset->stun1sa.sin_addr.s_addr); ofs+=4;
    set_u16(buf+ofs, addrset->stun1sa.sin_port); ofs+=2;  // nwbo
}
void get_addrset(char *buf, ClientAddressSet *outaddrset) {
    size_t ofs=0;
    outaddrset->id=get_u32(buf); ofs=4;
    outaddrset->sendersa.sin_addr.s_addr=get_u32(buf+ofs); ofs+=4;
    outaddrset->sendersa.sin_port=get_u16(buf+ofs); ofs+=2;
    outaddrset->stun0sa.sin_addr.s_addr=get_u32(buf+ofs); ofs+=4;
    outaddrset->stun0sa.sin_port=get_u16(buf+ofs); ofs+=2;
    outaddrset->stun1sa.sin_addr.s_addr=get_u32(buf+ofs); ofs+=4;
    outaddrset->stun1sa.sin_port=get_u16(buf+ofs); ofs+=2;    
}
int get_addrset_size() { return 4+ 4+2 + 4+2 + 4+2; }

double now() {
    struct timeval tmv;
    gettimeofday( &tmv, NULL );
    return tmv.tv_sec  + (double)(tmv.tv_usec) / 1000000.0f;
}



int32_t set_socket_nonblock(int fd) {                                                                          
    int flags = fcntl(fd, F_GETFL, 0);                                                                         
    assert(flags >= 0);                                                                                        
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);                                                             
}

bool is_same_sa_in(struct sockaddr_in *a0, struct sockaddr_in *a1) {
    fprintf(stderr,"is_same_sa_in: %s:%d <> %s:%d\n", inet_ntoa(a0->sin_addr),ntohs(a0->sin_port), inet_ntoa(a1->sin_addr), ntohs(a1->sin_port));
    return (a0->sin_addr.s_addr == a1->sin_addr.s_addr && a0->sin_port == a1->sin_port );
}
