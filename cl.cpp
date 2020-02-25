// punch cl
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
#include <fcntl.h>
#include <sys/time.h>

#include "include/stun/msg.h"

inline uint32_t get_u32(const char *buf){ return *((uint32_t*)(buf)); }
inline void set_u32(char *buf, uint32_t v){ (*((uint32_t*)(buf))) = (uint32_t)(v) ; }
inline uint16_t get_u16(const char *buf){ return *((uint16_t*)(buf)); }
inline void set_u16(char *buf, uint16_t v){ (*((uint16_t*)(buf))) = (uint16_t)(v); }


double now() {
    struct timeval tmv;
    gettimeofday( &tmv, NULL );
    return tmv.tv_sec  + (double)(tmv.tv_usec) / 1000000.0f;
}

void dumpbin(const char*s, size_t l) {
    for(size_t i=0;i<l;i++){
        fprintf(stderr, "%02x ", s[i] & 0xff );
        if((i%8)==7) fprintf(stderr,"  ");
        if((i%16)==15) fprintf(stderr,"\n");
    }
    fprintf(stderr,"\n");
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

///////////

int send_binding_req_to(int fd, struct sockaddr_in *tosa) {
    size_t buf_len=200;
    char buf[buf_len];
    const uint8_t tsx_id[12]={0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08, 0x09,0x0a,0x0b,0x0c };//TODO: impl
    stun_msg_hdr *msg_hdr = (stun_msg_hdr*)buf;
    stun_msg_hdr_init(msg_hdr, STUN_BINDING_REQUEST, tsx_id);
    stun_attr_uint32_add(msg_hdr,STUN_ATTR_CHANGE_REQUEST,0x00000000);
    int l = stun_msg_len(msg_hdr);
    fprintf(stderr, "stun_start_stun: msghdrlen:%d\n",l);        
    // 最初のメッセージをstunサーバに送る
    int r=sendto(fd, buf, l, 0, (struct sockaddr*)(tosa), sizeof(*tosa));
    return r;
}


typedef enum {
    STUN_STATE_INIT = 0,
    STUN_STATE_STUN_STARTED = 1,
    STUN_STATE_STUN_RECEIVED_FIRST_BINDING_RESPONSE = 2,
    STUN_STATE_STUN_FINISHED = 3,
} stun_state_type;

class StunContext {
public:
    int fd;    
    stun_state_type state;
    struct sockaddr_in localsa;
    struct sockaddr_in stunprimsa;
    struct sockaddr_in stunaltsa;
    struct sockaddr_in mapped_first_sa;
    struct sockaddr_in mapped_second_sa;

    StunContext() {
    }
    int init() {
        state = STUN_STATE_INIT;
        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(fd<0) return -1;
        if(set_socket_nonblock(fd)<0) {
            close(fd);
            fprintf(stderr,"set_socket_nonblock failed\n");
            return -2;
        }

        struct sockaddr_in origsi;
        memset((char *) &origsi, 0, sizeof(origsi));
        origsi.sin_family = AF_INET;
        int r=inet_aton("0.0.0.0", &origsi.sin_addr);
        assert(r==1);
        origsi.sin_port = 0; // any port
        r=bind(fd,(struct sockaddr*)&origsi,sizeof(origsi));
        if(r<0) {
            close(fd);        
            fprintf(stderr,"bind failed:%s\n",strerror(errno));        
            return -3;
        }
        memset((char *) &stunprimsa, 0, sizeof(stunprimsa));
        socklen_t sl=sizeof(localsa);
        r=getsockname(fd,(struct sockaddr*)&localsa,&sl);
        if(r<0) {
            close(fd);
            fprintf(stderr,"getsockname failed:%s\n",strerror(errno));
            return -4;
        }
        fprintf(stderr,"local bind addr: %s:%d\n", inet_ntoa(localsa.sin_addr), ntohs(localsa.sin_port));        
        return 0;
    }
    int start(const char *sv,uint16_t port) {
        stunprimsa.sin_family = AF_INET;
        int r=inet_aton(sv, &stunprimsa.sin_addr);
        if(r<0) {
            fprintf(stderr,"invalid sv addr:%s\n",sv);
            return -1;
        }
        stunprimsa.sin_port = htons(port);
        state = STUN_STATE_STUN_STARTED;

        r=send_binding_req_to(fd,&stunprimsa);
        if(r<0) fprintf(stderr,"send_binding_req_to error\n");
        return r;
    }

    void update() {
        struct sockaddr_in sa;
        socklen_t slen=sizeof(sa);
        char buf[200];
        int r=recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr*)(&sa), &slen);
        if(r<0) {
            if(errno==EAGAIN) {
                return;
            } else {
                fprintf(stderr,"recvfrom error: %d,%s\n",errno,strerror(errno));
            }
            return;
        }

        stun_msg_hdr *msg_hdr=(stun_msg_hdr*)buf;
        const stun_attr_hdr *attr_hdr=NULL;

        if(!stun_msg_verify(msg_hdr,r)) {
            fprintf(stderr,"invalid stun message\n");
            return;
        }

        switch(stun_msg_type(msg_hdr)) {
        case STUN_BINDING_RESPONSE:
            fprintf(stderr,"binding response\n");
            dumpbin(buf,r);
            break;
        case STUN_BINDING_ERROR_RESPONSE:
            fprintf(stderr,"binding error response\n");
            dumpbin(buf,r);
            return;
        default:
            fprintf(stderr,"stun msgtype not handled:%d\n", stun_msg_type(msg_hdr));
            return;
        }

        // OK, then parse attrs
        while((attr_hdr=stun_msg_next_attr(msg_hdr,attr_hdr))!=NULL) {
            switch(stun_attr_type(attr_hdr)) {
            case STUN_ATTR_MAPPED_ADDRESS:
                {
                    struct sockaddr sa;
                    stun_attr_sockaddr_read((stun_attr_sockaddr*)attr_hdr,&sa);
                    struct sockaddr_in *sap=(struct sockaddr_in*)&sa;
                    fprintf(stderr,"mapped addr: %s:%d\n", inet_ntoa(sap->sin_addr), ntohs(sap->sin_port));
                    if(state==STUN_STATE_STUN_STARTED) {
                        memcpy(&mapped_first_sa,sap,sizeof(*sap));                    
                    } else {
                        memcpy(&mapped_second_sa,sap,sizeof(*sap));                                        
                    }
                }
                break;
            case STUN_ATTR_RESPONSE_ORIGIN:
                {
                    struct sockaddr sa;
                    stun_attr_sockaddr_read((stun_attr_sockaddr*)attr_hdr,&sa);
                    struct sockaddr_in *sap=(struct sockaddr_in*)&sa;
                    fprintf(stderr,"response origin: %s:%d\n", inet_ntoa(sap->sin_addr), ntohs(sap->sin_port));
                }
                break;
            case STUN_ATTR_OTHER_ADDRESS:
                {
                    struct sockaddr sa;
                    stun_attr_sockaddr_read((stun_attr_sockaddr*)attr_hdr,&sa);
                    struct sockaddr_in *sap=(struct sockaddr_in*)&sa;
                    fprintf(stderr,"other addr: %s:%d\n", inet_ntoa(sap->sin_addr), ntohs(sap->sin_port));
                    memcpy(&stunaltsa,sap,sizeof(*sap));
                }
                break;
            case STUN_ATTR_XOR_MAPPED_ADDRESS:
                {
                    struct sockaddr sa;
                    int r=stun_attr_xor_sockaddr_read((stun_attr_xor_sockaddr *)attr_hdr, msg_hdr, &sa);
                    struct sockaddr_in *sap=(struct sockaddr_in*)&sa;
                    fprintf(stderr,"xor mapped addr: %s:%d\n", inet_ntoa(sap->sin_addr), ntohs(sap->sin_port));
                }
                break;
            }
        }

        if(state==STUN_STATE_STUN_STARTED) {
            fprintf(stderr,"received first stun binding response\n");
            state = STUN_STATE_STUN_RECEIVED_FIRST_BINDING_RESPONSE;
            fprintf(stderr,"sending second bindreq to %s:%d\n", inet_ntoa(stunaltsa.sin_addr), ntohs(stunaltsa.sin_port));
            send_binding_req_to(fd,&stunaltsa);
        } else if(state==STUN_STATE_STUN_RECEIVED_FIRST_BINDING_RESPONSE) {
            fprintf(stderr,"received second stun binding response from alterpeer, stun finished!\n");
            state=STUN_STATE_STUN_FINISHED;
        }
    }
};


///////////////

class PunchTarget {
public:

};
    
int send_update_to_sig(int fd, struct sockaddr_in *sigsa, struct sockaddr_in *sa0, struct sockaddr_in *sa1, int room_id) {
    const int bufsz=4+4+(4+2)*2;
    char buf[bufsz];
    set_u32(buf,0xffffffff); // magic number
    set_u32(buf+4,room_id);
    set_u32(buf+4+4,sa0->sin_addr.s_addr); //LE as is
    set_u16(buf+4+4+4,sa0->sin_port);
    set_u32(buf+4+4+4+2,sa1->sin_addr.s_addr); //LE as is
    set_u16(buf+4+4+4+2+4,sa1->sin_port);

    int r=sendto(fd,buf,bufsz,0,(struct sockaddr*)sigsa,sizeof(*sigsa));
    fprintf(stderr,"sending sigsv(%s:%d) :%d\n",inet_ntoa(sigsa->sin_addr),ntohs(sigsa->sin_port),r);
    return r;
    
}
/////////////

int main(int argc, char* argv[]) {
    if(argc!=2) {
        printf("arg: server_ip\n");
        return 1;
    }
    StunContext *ctx=new StunContext();
    if(ctx->init()<0) {
        fprintf(stderr,"cant init stun\n");
        return 1;
    }
    if(ctx->start(argv[1],3478)<0) {
        fprintf(stderr,"cant start stun\n");
        return 1;
    }

    while(1) {
        usleep(10*1000);
        ctx->update();
        if(ctx->state==STUN_STATE_STUN_FINISHED) {
            break;
        }
    }
    fprintf(stderr,"stun finished, start punch\n");
    double last_time=now();
    int room_id=123;
    struct sockaddr_in sigsa;
    int r=inet_aton(argv[1],&sigsa.sin_addr);
    sigsa.sin_port=htons(9999);
    assert(r==1);
    while(1) {
        usleep(10*1000);
        double nt=now();
        if(last_time<nt-0.5){
            last_time = nt;
            fprintf(stderr,".");

            // to signaling server
            send_update_to_sig(ctx->fd, &sigsa, &ctx->mapped_first_sa, &ctx->mapped_second_sa, room_id);

            struct sockaddr_in sa;
            socklen_t slen=sizeof(sa);
            char buf[200];
            int r=recvfrom(ctx->fd, buf, sizeof(buf), 0, (struct sockaddr*)(&sa), &slen);
            if(r<0) {
                if(errno!=EAGAIN) { 
                    fprintf(stderr,"recvfrom error: %d,%s\n",errno,strerror(errno));
                    break;
                }
            } else {
                fprintf(stderr,"received %d byte dgram\n",r);
                if(r<18) {
                    fprintf(stderr,"dgram too short\n");
                    continue;
                }
                uint32_t magic=get_u32(buf);
                int32_t room_id=get_u32(buf+4);
                struct sockaddr_in sendersa;
                sendersa.sin_addr.s_addr=get_u32(buf+4+4);
                sendersa.sin_port=get_u16(buf+4+4+4);
                int32_t cl_num=get_u32(buf+4+4+4+2);
                fprintf(stderr, "room_id:%d cl_num:%d sender:%s:%d\n",room_id,cl_num, inet_ntoa(sendersa.sin_addr),ntohs(sendersa.sin_port));
                if(r>=18+(cl_num*6)) {
                    size_t ofs=4+4+4+2+4;
                    for(int i=0;i<cl_num;i++) {
                        struct sockaddr_in sa;
                        sa.sin_addr.s_addr=get_u32(buf+ofs);
                        sa.sin_port=get_u16(buf+ofs+4);// receive nwbo
                        ofs+=6;
                        fprintf(stderr, "target addr: %s:%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
                        if( is_same_sa_in(&sa,&ctx->mapped_first_sa)) {
                            fprintf(stderr, "skipping local addr\n");
                        } else {
                            fprintf(stderr, "found target addr\n");
                        }
                    }
                }
            }
        }
    }
    return 0;
}

