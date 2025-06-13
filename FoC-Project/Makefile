CXXFLAGS = -g -Wall

# specify the build target
TARGETS = bin/server bin/client

# specify the object files that make up the server
SERVER_OBJS = obj/server.o obj/crypto.o obj/utility.o
CLIENT_OBJS = obj/client.o obj/crypto.o obj/utility.o

all: $(TARGETS)

bin/server: $(SERVER_OBJS)
	$(CXX) $(CXXFLAGS) -o bin/server $(SERVER_OBJS) -lcrypto

bin/client: obj/client.o
	$(CXX) $(CXXFLAGS) -o bin/client $(CLIENT_OBJS) -lcrypto

obj/server.o: server.cpp
	$(CXX) $(CXXFLAGS) -c server.cpp -o obj/server.o

obj/client.o: client.cpp
	$(CXX) $(CXXFLAGS) -c client.cpp -o obj/client.o

obj/crypto.o: crypto.cpp
	$(CXX) $(CXXFLAGS) -c crypto.cpp -o obj/crypto.o -lcrypto

obj/utility.o: utility.cpp
	$(CXX) $(CXXFLAGS) -c utility.cpp -o obj/utility.o -lcrypto
clean:
	rm -f bin/* obj/*

	

