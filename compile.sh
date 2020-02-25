g++ -c util.cpp 
g++ -o cl cl.cpp libstunmsg.a util.o
g++ -o sig sig.cpp util.o
