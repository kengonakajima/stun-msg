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

#include "util.h"




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
    nat_type detectNATType() {
        if(mapped_first_sa.sin_addr.s_addr != mapped_second_sa.sin_addr.s_addr) return NAT_TYPE_IP_DIFFER;
        if(mapped_first_sa.sin_addr.s_addr == mapped_second_sa.sin_addr.s_addr &&
           mapped_first_sa.sin_port == mapped_second_sa.sin_port ) {
            return NAT_TYPE_IP_PORT_STATIC;
        } else {
            return NAT_TYPE_IP_PORT_DYNAMIC;
        }
    }
};


///////////////
class Target {
public:
    ClientAddressSet addrset;
    int echo_cnt;
    Target() : echo_cnt(0) {}
};

Target g_targets[16];
int g_targets_used=0;
void ensureTarget(ClientAddressSet *addrset) {
    for(int i=0;i<g_targets_used;i++) {
        if(g_targets[i].addrset.id==addrset->id) {
            return;
        }
    }
    if(g_targets_used==elementof(g_targets)) {
        fprintf(stderr,"### targets full! cant add\n");
        return;
    }
    fprintf(stderr,"### Adding target client_id:%d sender:%s:%d\n", addrset->id, inet_ntoa(addrset->sendersa.sin_addr), ntohs(addrset->sendersa.sin_port));
    memcpy(&g_targets[g_targets_used],addrset,sizeof(*addrset));
    g_targets_used++;
}
int send_update_to_sig(int fd, struct sockaddr_in *sigsa, struct sockaddr_in *sa0, struct sockaddr_in *sa1, int room_id, int client_id ) {
    size_t ofs=0;
    char buf[200];
    set_u32(buf+ofs,0xffffffff); ofs+=4; // magic number
    set_u32(buf+ofs,room_id); ofs+=4;
    set_u32(buf+ofs,client_id); ofs+=4;
    set_u32(buf+ofs,sa0->sin_addr.s_addr); ofs+=4; 
    set_u16(buf+ofs,sa0->sin_port); ofs+=2; // nwbo
    set_u32(buf+ofs,sa1->sin_addr.s_addr); ofs+=4; 
    set_u16(buf+ofs,sa1->sin_port); ofs+=2;  // nwbo

    int r=sendto(fd,buf,ofs,0,(struct sockaddr*)sigsa,sizeof(*sigsa));
    fprintf(stderr,"sending msg to sigsv(%s:%d) r:%d\n",inet_ntoa(sigsa->sin_addr),ntohs(sigsa->sin_port),r);
    return r;
    
}
/////////////

int main(int argc, char* argv[]) {
    if(argc!=5) {
        printf("arg: server_ip client_id room_id room_member_num\n");
        return 1;
    }
    char *svaddr=argv[1];
    int client_id=atoi(argv[2]);
    int room_id=atoi(argv[3]);
    int room_member_num=atoi(argv[4]);
    
    StunContext *ctx=new StunContext();
    if(ctx->init()<0) {
        fprintf(stderr,"cant init stun\n");
        return 1;
    }
    if(ctx->start(svaddr,3478)<0) {
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

    fprintf(stderr,"stun finished! detecting NAT type:%d\n", ctx->detectNATType());
    if(ctx->detectNATType()!=NAT_TYPE_IP_PORT_STATIC) {
        fprintf(stderr, "Incompatible NAT type. IP address or port number is dynamic\n");
        return 1;
    }
    
    fprintf(stderr,"starting signaling\n==========================\n");

    /////
    
    double last_time=0;
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
            send_update_to_sig(ctx->fd, &sigsa, &ctx->mapped_first_sa, &ctx->mapped_second_sa, room_id, client_id);

        }
        struct sockaddr_in sa;
        socklen_t slen=sizeof(sa);
        char buf[200];
        int r=recvfrom(ctx->fd, buf, sizeof(buf), 0, (struct sockaddr*)(&sa), &slen);
        if(r<=0) {
            if(errno!=EAGAIN) { 
                fprintf(stderr,"recvfrom error: %d,%s\n",errno,strerror(errno));
                break;
            } else {
                    
            }
        } else {
            fprintf(stderr,"received %d byte dgram\n",r);
            if(r<18) {
                fprintf(stderr,"dgram too short\n");
                continue;
            }
            size_t ofs=0;
            uint32_t magic=get_u32(buf); ofs+=4;
            int32_t room_id=get_u32(buf+ofs); ofs+=4;
            int32_t cl_num=get_u32(buf+ofs); ofs+=4;
            fprintf(stderr, "room_id:%d cl_num:%d sender:%s:%d\n",room_id,cl_num, inet_ntoa(sa.sin_addr),ntohs(sa.sin_port));
            if(r<ofs+(cl_num*get_addrset_size())) {
                fprintf(stderr,"need more data\n");
                continue;
            }
            for(int i=0;i<cl_num;i++) {
                ClientAddressSet addrset;
                get_addrset(buf+ofs,&addrset);
                ofs+=get_addrset_size();
                fprintf(stderr, "room cl [%d] cl_id:%d sender:%s:%d stun0:%s:%d stun1:%s:%d\n",
                        i,
                        addrset.id,
                        inet_ntoa(addrset.sendersa.sin_addr), ntohs(addrset.sendersa.sin_port),
                        inet_ntoa(addrset.stun0sa.sin_addr), ntohs(addrset.stun0sa.sin_port),
                        inet_ntoa(addrset.stun1sa.sin_addr), ntohs(addrset.stun1sa.sin_port) );
                
                if(addrset.id==client_id) {
                    fprintf(stderr, "skipping myself\n");
                } else {
                    fprintf(stderr, "found target addr\n");
                    ensureTarget(&addrset);
                }
            }
        }
        if(g_targets_used == (room_member_num-1) ) {
            fprintf(stderr, "### Room member target number OK : %d\n", g_targets_used);
            break;
        }
    }

    int nat_ok_count=0;
    for(int i=0;i<g_targets_used;i++) {
        if(g_targets[i].addrset.detectNATType()==NAT_TYPE_IP_PORT_STATIC)nat_ok_count++;
    }
    if(nat_ok_count<room_member_num-1) {
        fprintf(stderr, "Need %d target(s), but only %d are in NAT type2..\n", room_member_num-1, nat_ok_count);
        return 1;
    }
    
    fprintf(stderr, "### now we have all members (%d) set up! start ping test\n", g_targets_used );
    while(1) {
        usleep(10*1000);
        double nt=now();
        static int trial=0;
        if(last_time<nt-0.5){
            trial++;
            last_time = nt;

            // to signaling server
            for(int i=0;i<g_targets_used;i++) {
                fprintf(stderr, "trial:%d i:%d id:%d echo:%d %s:%d %s:%d %s:%d\n",
                        trial, i, g_targets[i].addrset.id, g_targets[i].echo_cnt,
                        inet_ntoa(g_targets[i].addrset.sendersa.sin_addr), ntohs(g_targets[i].addrset.sendersa.sin_port),
                        inet_ntoa(g_targets[i].addrset.stun0sa.sin_addr), ntohs(g_targets[i].addrset.stun0sa.sin_port),
                        inet_ntoa(g_targets[i].addrset.stun1sa.sin_addr), ntohs(g_targets[i].addrset.stun1sa.sin_port) );
                char buf[4] = {'h','o','g','e'};
                struct sockaddr_in destsa;
                destsa.sin_addr.s_addr = g_targets[i].addrset.stun0sa.sin_addr.s_addr;
                destsa.sin_port = g_targets[i].addrset.stun0sa.sin_port;
                
                int r=sendto(ctx->fd,buf,4,0,(struct sockaddr*)&destsa,sizeof(destsa));
                fprintf(stderr,"sendto result:%d to:%s:%d\n",r,inet_ntoa(destsa.sin_addr),ntohs(destsa.sin_port));

            }
        }
        struct sockaddr_in sa;
        socklen_t slen=sizeof(sa);
        char buf[4];
        int r=recvfrom(ctx->fd, buf, sizeof(buf), 0, (struct sockaddr*)(&sa), &slen);
        if(r<=0) {
            if(errno!=EAGAIN) { 
                fprintf(stderr,"recvfrom error: %d,%s\n",errno,strerror(errno));
                break;
            } else {
            }
        } else {
            if(buf[0]=='h'&&buf[1]=='o'&&buf[2]=='g'&&buf[3]=='e') {
                
                fprintf(stderr,"recvfrom ret:%d addr:%s:%d\n", r, inet_ntoa(sa.sin_addr), ntohs(sa.sin_port));
            }
        }
        
        
    }

    return 0;
}

