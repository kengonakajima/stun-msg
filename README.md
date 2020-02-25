This is a public domain implementation in C, C++ and Python of the STUN message
(decoder and encoder), based on RFCs [5246](http://www.iana.org/go/rfc5246),
[5389](http://www.iana.org/go/rfc5389), [5766](http://www.iana.org/go/rfc5766),
[5780](http://www.iana.org/go/rfc5780), [6062](http://www.iana.org/go/rfc6062),
and [6156](http://www.iana.org/go/rfc6156).

Check the full documentation:

  * [How to Use the C library](https://github.com/guibv/stun-msg/wiki/How-to-use-the-C-library)
  * [How to Use the C++ library](https://github.com/guibv/stun-msg/wiki/How-to-use-the-CPP-library)
  * [How to Use the Python library](https://github.com/guibv/stun-msg/wiki/How-to-use-the-Python-library)


How to test UDP hole punching:

1. start a stunserver(stuntman) in a host that has 2 global ip address and 2 NICs (primalIP, altIP).
2. make a host with a global ip for signaling server (signaling host server)
3. On signaling host server, compile "sig" with compile.sh
4. start ```sig 9999``` on signaling host server.
5. Compile "cl" on some client machines
6. start first "cl" with  ```./cl primalIP client0_id room_id room_member_num```
7. start second "cl" with ```./cl primalIP client1_id room_id room_member_num```
8. "cl" performs STUN(RFC5780) first and then signaling, punching.

"cl" Example command line for 3 clients (client_ids:100,101,102 room_id:555 nummember:3)

```
./cl 11.22.33.44 100 555 3
./cl 11.22.33.44 101 555 3
./cl 11.22.33.44 102 555 3
```

