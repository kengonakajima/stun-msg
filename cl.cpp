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

/////////

typedef enum {
    STUN_STATE_INIT = 0,
    STUN_STATE_STUN_STARTED = 1,
    STUN_STATE_STUN_RECEIVED_FIRST_BINDING_RESPONSE = 2,
    STUN_STATE_STUN_FINISHED = 3,
} stun_state_type;

typedef struct _stun_ctx {
    int fd; 
    stun_state_type state;
    struct sockaddr_in localsa;
    struct sockaddr_in stunprimsa;
    struct sockaddr_in stunaltsa;
    struct sockaddr_in mapped_first_sa;
    struct sockaddr_in mapped_second_sa;
} stun_ctx;
int stun_init(stun_ctx *ctx) {
    memset(ctx,0,sizeof(*ctx));
    ctx->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(ctx->fd<0) return -1;

    if(set_socket_nonblock(ctx->fd)<0) {
        close(ctx->fd);
        fprintf(stderr,"set_socket_nonblock failed\n");
        return -2;
    }

    struct sockaddr_in origsi;
    memset((char *) &origsi, 0, sizeof(origsi));
    origsi.sin_family = AF_INET;
    int r=inet_aton("0.0.0.0", &origsi.sin_addr);
    assert(r==1);
    origsi.sin_port = 0; // any port
    
    r=bind(ctx->fd,(struct sockaddr*)&origsi,sizeof(origsi));
    if(r<0) {
        close(ctx->fd);        
        fprintf(stderr,"bind failed:%s\n",strerror(errno));        
        return -3;
    }
    ctx->state = STUN_STATE_INIT;
    memset((char *) &ctx->stunprimsa, 0, sizeof(ctx->stunprimsa));

    socklen_t sl=sizeof(ctx->localsa);
    r=getsockname(ctx->fd,(struct sockaddr*)&ctx->localsa,&sl);
    if(r<0) {
        close(ctx->fd);                
        fprintf(stderr,"getsockname failed:%s\n",strerror(errno));
        return -4;
    }
    fprintf(stderr,"local bind addr: %s:%d\n", inet_ntoa(ctx->localsa.sin_addr), ntohs(ctx->localsa.sin_port));        
    return 0;
}
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
int stun_start_stun(stun_ctx *ctx, const char *sv,uint16_t port) {
    ctx->stunprimsa.sin_family = AF_INET;
    int r=inet_aton(sv, &ctx->stunprimsa.sin_addr);
    if(r<0) {
        fprintf(stderr,"invalid sv addr:%s\n",sv);
        return -1;
    }
    ctx->stunprimsa.sin_port = htons(port);
    ctx->state = STUN_STATE_STUN_STARTED;

    r=send_binding_req_to(ctx->fd,&ctx->stunprimsa);
    if(r<0) fprintf(stderr,"send_binding_req_to error\n");
    return r;
}

void stun_update(stun_ctx *ctx) {
    struct sockaddr_in sa;
    socklen_t slen=sizeof(sa);
    char buf[200];
    int r=recvfrom(ctx->fd, &buf, sizeof(buf), 0, (struct sockaddr*)(&sa), &slen);
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
                if(ctx->state==STUN_STATE_STUN_STARTED) {
                    memcpy(&ctx->mapped_first_sa,sap,sizeof(*sap));                    
                } else {
                    memcpy(&ctx->mapped_second_sa,sap,sizeof(*sap));                                        
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
                memcpy(&ctx->stunaltsa,sap,sizeof(*sap));
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

    if(ctx->state==STUN_STATE_STUN_STARTED) {
        fprintf(stderr,"received first stun binding response\n");
        ctx->state = STUN_STATE_STUN_RECEIVED_FIRST_BINDING_RESPONSE;
        fprintf(stderr,"sending second bindreq to %s:%d\n", inet_ntoa(ctx->stunaltsa.sin_addr), ntohs(ctx->stunaltsa.sin_port));
        send_binding_req_to(ctx->fd,&ctx->stunaltsa);
    } else if(ctx->state==STUN_STATE_STUN_RECEIVED_FIRST_BINDING_RESPONSE) {
        fprintf(stderr,"received second stun binding response from alterpeer, stun finished!\n");
        ctx->state=STUN_STATE_STUN_FINISHED;

        // print result of stun basic behaviour test

    }
}

int main(int argc, char* argv[]) {
    if(argc!=2) {
        printf("arg: server_ip\n");
        return 1;
    }
    stun_ctx ctx;
    stun_init(&ctx);
    stun_start_stun(&ctx,argv[1],3478);
    while(1) {
        usleep(10*1000);
        stun_update(&ctx);
        if(ctx.state==STUN_STATE_STUN_FINISHED) {
            break;
        }
    }
    fprintf(stderr,"stun finished\n");
    return 0;
}

#if 0
{
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

    switch(stun_msg_type(msg_hdr)) {
    case STUN_BINDING_RESPONSE:
        fprintf(stderr,"binding response\n");
        dumpbin(buf,r);
        break;
    case STUN_BINDING_ERROR_RESPONSE:
        fprintf(stderr,"binding error response\n");
        dumpbin(buf,r);
        return 1;
        break;
    default:
        fprintf(stderr,"stun msg type not handled\n");
        return 1;
        break;
    }

    while((attr_hdr=stun_msg_next_attr(msg_hdr,attr_hdr))!=NULL) {
        switch(stun_attr_type(attr_hdr)) {
        case STUN_ATTR_MAPPED_ADDRESS:
            {
                struct sockaddr sa;
                stun_attr_sockaddr_read((stun_attr_sockaddr*)attr_hdr,&sa);
                struct sockaddr_in *sap=(struct sockaddr_in*)&sa;
                fprintf(stderr,"mapped addr: %s:%d\n", inet_ntoa(sap->sin_addr), ntohs(sap->sin_port));
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
    
    
    close(s);
    return 0;
}



#endif
