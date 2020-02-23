#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#ifndef elementof
#define elementof(x) ( (int)(sizeof(x) / sizeof(x[0])))
#endif

inline uint32_t get_u32(const char *buf){ return *((uint32_t*)(buf)); }
inline void set_u32(char *buf, uint32_t v){ (*((uint32_t*)(buf))) = (uint32_t)(v) ; }

void dumpbin(const char*s, size_t l) {
    for(size_t i=0;i<l;i++){
        fprintf(stderr, "%02x ", s[i] & 0xff );
        if((i%8)==7) fprintf(stderr,"  ");
        if((i%16)==15) fprintf(stderr,"\n");
    }
    fprintf(stderr,"\n");
}

// signaling server

class Room {
public:
    int id; // -1 not used
    int cl_num;
    static const int MEMBER_MAX=4;
    struct sockaddr_in clsa[MEMBER_MAX];
    Room(int id) :id(id), cl_num(0) {
        memset(clsa,0,sizeof(clsa));
        fprintf(stderr,"Room constructed.id:%d\n",id);
    }
    int ensureClientAddr(struct sockaddr_in *a) {
        for(int i=0;i<cl_num;i++) {
            if(clsa[i].sin_addr.s_addr==a->sin_addr.s_addr && clsa[i].sin_port==a->sin_port) {
                fprintf(stderr,"ensureClientAddr: %s:%d is already added in room %d\n",
                        inet_ntoa(a->sin_addr), ntohs(a->sin_port), id);
                return 0;
            }
        }
        if(cl_num==MEMBER_MAX) {
            fprintf(stderr, "ensureClientAddr too many member in room %d\n",id);
            return -1;
        }
        memcpy( & clsa[cl_num], a, sizeof(*a));
        cl_num++;
        fprintf(stderr, "ensureClientAddr: added %s:%d in room %d\n", inet_ntoa(a->sin_addr), ntohs(a->sin_port),id);
        return 1;
    }
    void broadcastAddresses(int fd, int room_id) {
        const int bufsz=1+4+sizeof(struct sockaddr_in)*MEMBER_MAX; // cl_num(1byte) + room_id(4byte) + array of sockaddr_in
        char buf[bufsz];
        memset(buf,0,bufsz);
        buf[0]=cl_num;
        set_u32(buf+1,room_id);
        
        for(int i=0;i<cl_num;i++){
            memcpy(buf+1+4+i*sizeof(struct sockaddr_in), &clsa[i], sizeof(struct sockaddr_in));
        }
        int sendlen = 1+4+sizeof(struct sockaddr_in)*cl_num;        
        dumpbin(buf,sendlen);
        for(int i=0;i<cl_num;i++) {
            printf("broadcastAddresses: Sending addrs to %s:%d\n",
                   inet_ntoa(clsa[i].sin_addr), ntohs(clsa[i].sin_port));
            socklen_t slen = sizeof(struct sockaddr_in);
            int r=sendto(fd, buf,sendlen, 0, (struct sockaddr*)(&clsa[i]), slen);
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
Room *createRoom(int id, struct sockaddr_in *sa) {
    for(int i=0;i<elementof(g_rooms);i++) {
        if(g_rooms[i]==NULL) {
            g_rooms[i]=new Room(id);
            g_rooms[i]->ensureClientAddr(sa);
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
        char buf[4];
        struct sockaddr_in remotesa;
        socklen_t slen=sizeof(remotesa);
        r=recvfrom(s, buf, sizeof(buf), 0, (struct sockaddr*)(&remotesa), &slen);
        assert(r>=0);
        fprintf(stderr,"Received packet from %s:%d len:%d\n", inet_ntoa(remotesa.sin_addr), ntohs(remotesa.sin_port),r);
        if(r==4) {
            int room_id = (int)get_u32(buf);
            fprintf(stderr, "received room_id:%d\n",room_id);
            Room *room = findRoomById(room_id);
            if(room) {
                room->ensureClientAddr(&remotesa);
            } else {
                room = createRoom(room_id,&remotesa);
            }
            room->broadcastAddresses(s,room_id);
        }
    }
    close(s);
    return 0;
}