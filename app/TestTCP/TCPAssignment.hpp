/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <E/E_TimerModule.hpp>
#include <stdlib.h>     /* srand, rand */
#include <unistd.h>

typedef uint16_t u16;
typedef uint32_t u32;
typedef uint8_t u8;
typedef uint64_t u64;


namespace E
{
static const u32 MSS = 512;
static const u32 RECEIVE_BUF_SIZE = 51200;
static const u32 SEND_BUF_SIZE = 51200;
struct TcpUniqueID {
	u32 sourceIP;
	u16 sourcePort;
	u32 desIP;
	u16 desPort;
};


struct TCPHeader{			
	u16 sourcePort; 
	u16 desPort; 
	u32 sequence;
	u32 acknowledge; 
	u8 headerLength; 	
	u8 flag; 
	u16 window; 
	u16 checksum;
	u16 urgentDataPointer = 0; 				
};

enum SocketStates { S_CLOSED, S_LISTEN, S_SYN_SENT, S_SYN_RCVD, S_ESTABLISHED, S_CLOSE_WAIT, 
	                  S_FIN_WAIT_1, S_FIN_WAIT_2 ,S_LAST_ACK, S_CLOSING, S_TIME_WAIT, S_ANY};

struct Socket {
	int fd;
	int pid;
	int threeWayHandShake = 0;
	int connectId;
	bool alreadySentSYNACK = false;
	SocketStates socketState = S_CLOSED;
	
	bool isAlreadyBound = false;
	struct TcpUniqueID tcpUniqueID;

	u8* receiveBuf;
	u32 startCanRead = 0; //on receive buf
	u32 windowBase = 0;   //on receive buf
	u32 readyReceive;     //next byte I want to receive
	u16 rwnd = RECEIVE_BUF_SIZE;
	u16 peerWindow;        

	bool isWaitingRead = false;
	int readId;
	u32 readLength;
	u8* readBuf;

	u8* sendBuf = NULL;
	u32 sendBufHead = 0;  //on sending buf
	u32 sendBufTail = 0;  //on sending buf
	u32 firstSending;     //the first byte on-flight
	u32 nextSend;         //the next byte to send
	bool isWaitingWrite = false;
	int writeId;
	u32 writeLength;

	bool isWaitingClose = false;
	int closeId;
};

struct waitingAcceptSocket {
	u16 sourcePort;
	u32 sourceIP;
	int pid;
	int fd;
	bool isWaiting = false;
	UUID syscallUUID;
	struct sockaddr* address;
	socklen_t* addLength;
};

struct toBeEstablishedSockets {
	u16 sourcePort;
	u32 sourceIP;
	int pid;
	int backlog;
	std::vector<TcpUniqueID> socketList;
};

struct establishedSockets {
	u16 sourcePort;
	u32 sourceIP;
	int pid;
	std::vector<TcpUniqueID> socketList;
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
	int demArrive = 0;
	std::vector<Socket> socketList;
	std::vector<toBeEstablishedSockets> toBeEstablishedList;
	std::vector<establishedSockets> establishedList;
	std::vector<waitingAcceptSocket> waitingAcceptList;

private:
	int findSocket(int pid, int fd, SocketStates socketState);
	int findSocketByAddress(u16 port, u32 IP, SocketStates socketState);
	int findSocketByTCPUniqueID(TcpUniqueID tcpUniqueID, SocketStates socketState);
	bool checkValidBoundAddress(u16 expectedPort, u32 expectedIP, int sockFd);
	int findToBeEstablishedSockets(u16 port, u32 IP);
	int findWaitingAcceptSocket(u16 port, u32 IP);
	int findEstablishedSockets(u16 port, u32 IP);
	bool tryToFreeSendingBuf(int socIndex);
	int tryToSendPacket(int socIndex, u8* buf, u32 length);


	void syscall_socket(UUID syscallUUID, int pid, int param1, int param2);
	void syscall_bind(UUID syscallUUID, int pid, int param1, struct sockaddr* param2, socklen_t param3);
	void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
	void syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr* address, socklen_t addLength);
	void syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr* address, socklen_t* addLength);
	void syscall_read(UUID syscallUUID, int pid, int fd, u8* buf, u32 sendingLength);
	void syscall_write(UUID syscallUUID, int pid, int fd, u8* buf, u32 length);
	void syscall_close(UUID syscallUUID, int pid, int fd);
	void syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr* address, socklen_t* addLength);
	void syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr* address, socklen_t* addLength);
private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
