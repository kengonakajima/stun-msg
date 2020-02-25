rm cl sig *.o
g++ -g -c util.cpp 
g++ -g -o cl cl.cpp libstunmsg.a util.o
g++ -g -o sig sig.cpp util.o
