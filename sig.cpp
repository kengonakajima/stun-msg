#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "util.h"



class Room {
public:
    int id; // -1 not used
    int cl_num;
    static const int MEMBER_MAX=4;
    ClientAddressSet claddrs[MEMBER_MAX];
    Room(int id) :id(id), cl_num(0) {
        memset(claddrs,0,sizeof(claddrs));
        fprintf(stderr,"Room constructed.id:%d\n",id);
    }
    int ensureClientAddr(ClientAddressSet *addrset) {
        for(int i=0;i<cl_num;i++) {
            if(claddrs[i].id==addrset->id) {
                fprintf(stderr,"ensureClientAddr: clid %d is already added in room %d\n", addrset->id,id);
                return 0;
            }
        }
        if(cl_num==MEMBER_MAX) {
            fprintf(stderr, "ensureClientAddr too many member in room %d\n",id);
            return -1;
        }
        memcpy( & claddrs[cl_num], addrset, sizeof(*addrset));
        cl_num++;
        fprintf(stderr, "ensureClientAddr: added clid:%d in room %d\n", addrset->id, id);
        return 1;
    }
    void broadcastAddresses(int fd, int room_id, struct sockaddr_in *sendersa) {
        const int bufsz=4+4+4+(4+2)+sizeof(struct sockaddr_in)*MEMBER_MAX; // cl_num(1byte) + room_id(4byte) + array of sockaddr_in
        char buf[bufsz];
        size_t ofs=0;
        memset(buf,0,bufsz);
        set_u32(buf,0xffffffff); ofs+=4;
        set_u32(buf+ofs,room_id); ofs+=4;
        set_u32(buf+ofs,sendersa->sin_addr.s_addr); ofs+=4;
        set_u16(buf+ofs,sendersa->sin_port); ofs+=2; // nwbo
        set_u32(buf+ofs,cl_num); ofs+=4;
        for(int i=0;i<cl_num;i++){
            set_addrset(buf+ofs, &claddrs[i]);
            ofs+= get_addrset_size();
            fprintf(stderr, "broadcastAddresses: i:%d id:%d sendersa:%s:%d\n", i, claddrs[i].id, inet_ntoa(claddrs[i].sendersa.sin_addr), ntohs(claddrs[i].sendersa.sin_port));
        }
        dumpbin(buf,ofs);
        for(int i=0;i<cl_num;i++) {
            printf("broadcastAddresses: Sending addrs to %s:%d\n",
                   inet_ntoa(claddrs[i].sendersa.sin_addr), ntohs(claddrs[i].sendersa.sin_port));
            socklen_t slen = sizeof(struct sockaddr_in);
            int r=sendto(fd, buf,ofs, 0, (struct sockaddr*)(&claddrs[i].sendersa), slen);
            assert(r>=0);
            
        }
    }
};

const int ROOM_MAX=10;

Room *g_rooms[ROOM_MAX];
Room *findRoomById(int id) {
    for(int i=0;i<elementof(g_rooms);i++) {
        if(g_rooms[i]&&g_rooms[i]->id==id) return g_rooms[i];
    }
    return NULL;
}
Room *createRoom(int id, ClientAddressSet *addrset) {
    for(int i=0;i<elementof(g_rooms);i++) {
        if(g_rooms[i]==NULL) {
            g_rooms[i]=new Room(id);
            g_rooms[i]->ensureClientAddr(addrset);
            return g_rooms[i];
        }
    }
    fprintf(stderr, "createRoom: too many room\n");
    return NULL;
}

int main(int argc, char **argv) {
    if(argc!=2) {
        fprintf(stderr,"need port\n");
        return 1;
    }
    int port=atoi(argv[1]);
    
    struct sockaddr_in svsa;

    int s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    assert(s>0);

    memset((char *) &svsa, 0, sizeof(svsa));
    svsa.sin_family = AF_INET;
    svsa.sin_port = htons(port);
    svsa.sin_addr.s_addr =INADDR_ANY;
    
    int r;
    r=bind(s, (struct sockaddr*)(&svsa), sizeof(svsa));
    assert(r==0);

    while (1) {
        char buf[200];
        ClientAddressSet addrset;
        socklen_t slen=sizeof(addrset.sendersa);
        r=recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr*)(&addrset.sendersa), &slen);
        assert(r>=0);
        fprintf(stderr,"Received packet from %s:%d len:%d\n", inet_ntoa(addrset.sendersa.sin_addr), ntohs(addrset.sendersa.sin_port),r);
        if(r>0) {
            size_t ofs=0;
            uint32_t magic=get_u32(buf);
            ofs+=4;
            if(magic!=0xffffffff) {
                fprintf(stderr,"invalid magic:%x\n",magic);
                continue;
            }

            int room_id = (int)get_u32(buf+ofs);
            ofs+=4;
            addrset.stun0sa.sin_addr.s_addr=get_u32(buf+ofs); ofs+=4;
            addrset.stun0sa.sin_port=get_u16(buf+ofs); ofs+=2;
            addrset.stun1sa.sin_addr.s_addr=get_u16(buf+ofs); ofs+=4;
            addrset.stun1sa.sin_port=get_u16(buf+ofs); ofs+=2;
            fprintf(stderr, "received %d bytes, room_id:%d stun0sa:%s:%d stun1sa:%s:%d\n",
                    (int)ofs, room_id,
                    inet_ntoa(addrset.stun0sa.sin_addr), ntohs(addrset.stun0sa.sin_port),
                    inet_ntoa(addrset.stun1sa.sin_addr), ntohs(addrset.stun1sa.sin_port) );

            Room *room = findRoomById(room_id);
            if(room) {
                room = createRoom(room_id,&addrset);
            }
            // 利用可能なアドレスは、 remotesa(sigに送ってきたアドレス), sa0(STUNのprimary), sa1(STUNのalter)
            // の3つがある。 sigがSTUNサーバと同じマシンで動いてるが、ポート番号がSTUNとは違うため、
            // NATの挙動が dest port依存の場合は、3つとも違っている可能性がある。
            // サーバー側をできるだけ単純にして、複雑性の解決をできるだけピアに寄せるという設計にするならば、
            // 3つともすべてクライアントの情報として送る必要がある。
            room->ensureClientAddr(&addrset);
            room->broadcastAddresses(s,room_id,&addrset.sendersa);
        }
        usleep(10*1000);
    }
    close(s);
    return 0;
}
