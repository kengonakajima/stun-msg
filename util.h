#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/time.h>
#include <fcntl.h>
#include <assert.h>
#include <arpa/inet.h>

#ifndef elementof
#define elementof(x) ( (int)(sizeof(x) / sizeof(x[0])))
#endif


inline uint32_t get_u32(const char *buf){ return *((uint32_t*)(buf)); }
inline void set_u32(char *buf, uint32_t v){ (*((uint32_t*)(buf))) = (uint32_t)(v) ; }
inline uint16_t get_u16(const char *buf){ return *((uint16_t*)(buf)); }
inline void set_u16(char *buf, uint16_t v){ (*((uint16_t*)(buf))) = (uint16_t)(v); }

void dumpbin(const char*s, size_t l) ;

typedef enum {
              NAT_TYPE_IP_PORT_STATIC = 2,  // type 1/2
              NAT_TYPE_IP_PORT_DYNAMIC = 3, // type 3
              NAT_TYPE_IP_DIFFER = 4, // IP address differ, hole punch not available!
} nat_type;


// signaling server
class ClientAddressSet {
public:
    int id;
    struct sockaddr_in sendersa;
    struct sockaddr_in stun0sa;
    struct sockaddr_in stun1sa;
    ClientAddressSet() {}
    nat_type detectNATType() {
        if(stun0sa.sin_addr.s_addr != stun1sa.sin_addr.s_addr) return NAT_TYPE_IP_DIFFER;
        if(stun0sa.sin_addr.s_addr == stun1sa.sin_addr.s_addr &&
           stun0sa.sin_port == stun1sa.sin_port ) {
            return NAT_TYPE_IP_PORT_STATIC;
        } else {
            return NAT_TYPE_IP_PORT_DYNAMIC;
        }
    }
};

void set_addrset(char *buf, ClientAddressSet *addrset);
void get_addrset(char *buf, ClientAddressSet *outaddrset);
int get_addrset_size() ;
double now() ;



int32_t set_socket_nonblock(int fd);
bool is_same_sa_in(struct sockaddr_in *a0, struct sockaddr_in *a1);
