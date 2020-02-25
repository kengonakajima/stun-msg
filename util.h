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

// signaling server
class ClientAddressSet {
public:
    int id;
    struct sockaddr_in sendersa;
    struct sockaddr_in stun0sa;
    struct sockaddr_in stun1sa;
    ClientAddressSet() {}
};

void set_addrset(char *buf, ClientAddressSet *addrset);
void get_addrset(char *buf, ClientAddressSet *outaddrset);
int get_addrset_size() ;
double now() ;



int32_t set_socket_nonblock(int fd);
bool is_same_sa_in(struct sockaddr_in *a0, struct sockaddr_in *a1);
