/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

namespace E
{
int demArrive = 0;
//HELPER FUNCTION
uint64_t arrayToUINT64_inverse(const uint8_t* array, int length)
{
	assert(length <= (int)sizeof(uint64_t));
	uint64_t sum = 0;
	for(int k=0; k<length; k++)
	{
		sum += (((uint64_t)array[k]) << (8 * k));
	}
	return sum;
}

uint64_t arrayToUINT64_not_inverse(const uint8_t* array, int length)
{
	assert(length <= (int)sizeof(uint64_t));
	uint64_t sum = 0;
	for(int k=0; k<length; k++)
	{
		sum = (sum << 8) + ((uint64_t)array[k]);
	}
	return sum;
}

bool compareTwoBuf(const u8* buf1, const u8* buf2, int length){
	for (int i = 0; i < length; i++){
		if (buf1[i] != buf2[i])
			return false;
	}
	return true;
}

void writeBuf(const u8* buf, int length){
	for (int i = 0; i < length; i++){
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

bool samePortAndIP(u16 port1, u32 IP1, u16 port2, u32 IP2){
	return (port1 == port2 && (IP1 == 0 || IP2 == 0 || IP1 == IP2));
}

void printTcpUniqueID(TcpUniqueID id){
	std::cout << id.sourcePort << " " << id.sourceIP << " " << id.desPort << " " << id.desIP << std::endl;
}


bool sameTcpUniqueID(TcpUniqueID id1, TcpUniqueID id2){
	return (samePortAndIP(id1.sourcePort, id1.sourceIP, id2.sourcePort, id2.sourceIP)
		&& samePortAndIP(id1.desPort, id1.desIP, id2.desPort, id2.desIP));
}


sockaddr_in createSockaddr_in (u16 port, u32 IP) {
	struct sockaddr_in myAddr;
	socklen_t len = sizeof(myAddr);
	memset(&myAddr, 0, len);
	myAddr.sin_family = AF_INET;
	myAddr.sin_port = port;
	myAddr.sin_addr.s_addr = IP;
	return myAddr;		
}

int oneSum1(u8* buf, int length){
  int res = 0;
  while (length > 1){
    int temp = htons(*buf);

    res = res + temp;
    if ((res >> 16) & 1) res += 1;
    buf += 2;
    length -= 2;
  }

  if (length == 1){
    res += *((char*) buf);
  }
  if ((res >> 16) & 1) res += 1;
  res = ~res;
  return res;
}

uint16_t oneSum(const uint8_t* buffer, size_t size)
{
	bool upper = true;
	uint32_t sum = 0;
	for(size_t k=0; k<size; k++)
	{
		if(upper)
		{
			sum += buffer[k] << 8;
		}
		else
		{
			sum += buffer[k];
		}

		upper = !upper;
	}

	do
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}while((sum & 0xFFFF) != sum);

	if(sum == 0xFFFF)
		sum = 0;

	return (uint16_t)sum;
}

u32 addOneSum(u32 curSum, u8* buf, int length){
	u32 res = curSum;
	int i = 0;
	while (i + 1 < length){
		res += buf[i] << 8;
		res += buf[i + 1];
		i += 2;
	}
	//one byte left
	if (i < length) {
		res += buf[i];
	}
	return res;
}

u32 addOneSum1(u32 curSum, u8* buf, int length){
	bool upper = true;
	u32 sum = curSum;
	for(int k=0; k<length; k++)
	{
		if(upper)
		{
			sum += buf[k] << 8;
		}
		else
		{
			sum += buf[k];
		}
		upper = !upper;
	}

	return sum;
}

u16 findTcpChecksum(u32 sourceIP, u32 desIP, u8* buf, u16 length, u8* buf1 = NULL, u16 length1 = 0){
	
	u32 res = 0;
	u16 protocol = 6;protocol = htons(protocol);
	u16 tempLength = htons(length);
/*	printf("-------\n");

	writeBuf(((u8*) &sourceIP), 4);
	writeBuf(((u8*) &desIP), 4);
	writeBuf(((u8*) &protocol), 2);
	writeBuf(((u8*) &tempLength), 2);
	std::cout << length <<  " " << length1 << std::endl;*/

	res = addOneSum(res, (u8*) &sourceIP, 4);
	res = addOneSum(res, (u8*) &desIP, 4);
	res = addOneSum(res, (u8*) &protocol, 2);
	res = addOneSum(res, (u8*) &tempLength, 2);
	res = addOneSum(res, buf, (int)length);
	//writeBuf(buf, (int)length);
	//res = addOneSum(res, buf + 20, (int)length - 20);
	//writeBuf(buf + 20, (int) length - 20);
	if (buf1 != NULL && length1 != 0){
		//writeBuf(buf1, length1);
		res = addOneSum(res, buf1, (int)length1);
	}
	while (res>>16)
    res = (res & 0xffff) + (res >> 16);

	res = ~res;
	/*std::cout << (u16)res << std::endl;*/
	return (u16) res;
}

u16 findCheckSum(u8* buf, int length){
	u32 res = addOneSum(0, buf, length);
	while (res>>16)
    res = (res & 0xffff) + (res >> 16);

	res = ~res;
	return (u16) res;	
}

int add(int a, int b){
	return (a + b) % RECEIVE_BUF_SIZE;
}

int minus(int a, int b){
	if (b <= a) return a - b;
	return RECEIVE_BUF_SIZE - (b - a);
}

int addNum(int a, int b, int base){
	return (a + b) % base;
}

int minusNum(int a, int b, int base){
	if (b <= a) return a - b;
	return base - (b - a);
}

void copyData(u8* buf, int length, u8* desBuf, u32 from, u32 to){
	int i = from;
	int j = 0;
	while (length > 0){
		desBuf[i] = buf[j++];
		i = add(i, 1);
		length--;
	}
}


u16 getPort(struct sockaddr_in* address){
	return address->sin_port;
}

u32 getIP(struct sockaddr_in* address){
	return (address->sin_addr).s_addr;
}

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
}

void TCPAssignment::finalize()
{

}

int TCPAssignment::findSocket(int pid, int fd, SocketStates socketState){
	int foundIndex = -1;
	for (int i = 0; i < (int)socketList.size(); i++){
		if (socketList[i].pid == pid && socketList[i].pid == pid && (socketList[i].socketState == socketState || socketState == S_ANY)){
			return i;
		}
	}
	return foundIndex;
}

int TCPAssignment::findSocketByAddress(u16 port, u32 IP, SocketStates socketState){
	int foundIndex = -1;
	for (int i = 0; i < (int)socketList.size(); i++){
		if (samePortAndIP(port, IP, socketList[i].tcpUniqueID.sourcePort, socketList[i].tcpUniqueID.sourceIP) 
			  && (socketState == socketList[i].socketState || socketState == S_ANY)){
			return i;
		}
	}
	return foundIndex;
}

int TCPAssignment::findSocketByTCPUniqueID(TcpUniqueID tcpUniqueID, SocketStates socketState){
	for (int i = 0; i < (int)socketList.size(); i++){
		if (socketList[i].socketState != S_LISTEN)
		if ((socketState == socketList[i].socketState || socketState == S_ANY) && sameTcpUniqueID(tcpUniqueID, socketList[i].tcpUniqueID)){
			return i;
		}
	}
	return -1;
}

int TCPAssignment::findEstablishedSockets(u16 port, u32 IP){
	for (int i = 0; i < (int)establishedList.size(); i++){
		establishedSockets sockets = establishedList[i];
		if (samePortAndIP(port, IP, sockets.sourcePort, sockets.sourceIP)){
			return i;
		}
	}
	return -1;
}

int TCPAssignment::findWaitingAcceptSocket(u16 port, u32 IP){
	for (int i = 0; i < (int)waitingAcceptList.size(); i++){
		waitingAcceptSocket socket = waitingAcceptList[i];
		if (samePortAndIP(port, IP, socket.sourcePort, socket.sourceIP)){
			return i;
		}
	}
	return -1;
}



int TCPAssignment::findToBeEstablishedSockets(u16 port, u32 IP){
	for (int i = 0; i < (int) toBeEstablishedList.size(); i++){
		toBeEstablishedSockets sockets = toBeEstablishedList[i];
		if (samePortAndIP(port, IP, sockets.sourcePort, sockets.sourceIP) && (int)sockets.socketList.size() < sockets.backlog) {
			return i;
		}
	}
	return -1;
}

bool TCPAssignment::checkValidBoundAddress(u16 expectedPort, u32 expectedIP, int sockFd){
	for (int i = 0; i < (int)socketList.size(); i++){
		Socket tempSoc = socketList[i];
		u16 tempPort = tempSoc.tcpUniqueID.sourcePort;
		u32 tempIP = tempSoc.tcpUniqueID.sourceIP;

		if (tempSoc.fd != sockFd && samePortAndIP(tempPort, tempIP, expectedPort, expectedIP) && tempSoc.isAlreadyBound){
			return false;
		}
	}
	return true;
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1, int param2){
	int newFd = this->createFileDescriptor(pid);
	Socket newSocket;
	newSocket.fd = newFd;
	newSocket.pid = pid;
	socketList.push_back(newSocket);
	this->returnSystemCall(syscallUUID, newFd);
}


void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd,struct sockaddr* address, socklen_t addLength){
	int socIndex = findSocket(pid, fd, S_CLOSED);
	if (socIndex == -1){
		this->returnSystemCall(syscallUUID, -1);
		return;
	}
	u16 expectedPort = ntohs(getPort((sockaddr_in*)address));
	u32 expectedIP = ntohl(getIP((sockaddr_in*)address));
	//Check if the expected address can be used
	if (!checkValidBoundAddress(expectedPort,expectedIP,socIndex)){
		this->returnSystemCall(syscallUUID, -1);
	}
	//Start binding
	socketList[socIndex].tcpUniqueID.sourceIP = expectedIP;
	socketList[socIndex].tcpUniqueID.sourcePort = expectedPort;
	socketList[socIndex].isAlreadyBound = true;
	socketList[socIndex].fd = fd;
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog){
	int socIndex = findSocket(pid, fd, S_CLOSED);
	if (socIndex == -1){
		this->returnSystemCall(syscallUUID, -1);
	}
	socketList[socIndex].socketState = S_LISTEN;
	u16 sourcePort = socketList[socIndex].tcpUniqueID.sourcePort;
	u32 sourceIP = socketList[socIndex].tcpUniqueID.sourceIP;

	struct waitingAcceptSocket newWaitingAcceptSocket;
	struct toBeEstablishedSockets newToBeEstablishedSockets;
	struct establishedSockets newEstablishedSockets;
	newWaitingAcceptSocket.sourceIP = sourceIP;
	newWaitingAcceptSocket.sourcePort = sourcePort;
	newWaitingAcceptSocket.pid = pid;

	newToBeEstablishedSockets.sourceIP = sourceIP;
	newToBeEstablishedSockets.sourcePort = sourcePort;
	newToBeEstablishedSockets.pid = pid;
	newToBeEstablishedSockets.backlog = backlog;

	newEstablishedSockets.sourceIP = sourceIP;
	newEstablishedSockets.sourcePort = sourcePort;
	newEstablishedSockets.pid = pid;

	waitingAcceptList.push_back(newWaitingAcceptSocket);
	toBeEstablishedList.push_back(newToBeEstablishedSockets);
	establishedList.push_back(newEstablishedSockets);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockadd* address, socklen_t addLength){
	


}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd,struct sockaddr* address, socklen_t* addLength){
	//find the calling socket
	int socIndex = findSocket(pid, fd, S_LISTEN);
	if (socIndex == -1){
		this->returnSystemCall(syscallUUID, -1);
	}
	u16 sourcePort = socketList[socIndex].tcpUniqueID.sourcePort;
	u32 sourceIP = socketList[socIndex].tcpUniqueID.sourceIP;
	//If there is now at least an etablished socket, then get it
	int establishedSocketsIndex = findEstablishedSockets(sourcePort, sourceIP);
  if (establishedList[establishedSocketsIndex].socketList.size() > 0){
  	//pop out the first established socket
  	u16 tempPort = establishedList[establishedSocketsIndex].socketList[0].desPort;
  	u32 tempIP = establishedList[establishedSocketsIndex].socketList[0].desIP;
  	establishedList[establishedSocketsIndex].socketList.erase(establishedList[establishedSocketsIndex].socketList.begin());
  	//Prepare return value
  	sockaddr_in temp;
  	*((sockaddr_in *) address) = createSockaddr_in(htons(tempPort), htonl(tempIP));
		*((int *) addLength) = sizeof (temp);
  	
  	this->returnSystemCall(syscallUUID, fd);
  } else {
  	//Else just wait until an ACK for three-way handshake is received
  	int waitingAcceptIndex = findWaitingAcceptSocket(sourcePort, sourceIP);
  	waitingAcceptList[waitingAcceptIndex].isWaiting = true;
  	waitingAcceptList[waitingAcceptIndex].syscallUUID = syscallUUID;
  	waitingAcceptList[waitingAcceptIndex].address = address;
  	waitingAcceptList[waitingAcceptIndex].addLength = addLength;
  	waitingAcceptList[waitingAcceptIndex].fd = fd;
  }
  
	
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, char* buf, int sendingLength){

}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, char* buf, int sendingLength){

}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){

}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd,struct sockaddr* address, socklen_t* addLength){
	//Get the source address
	int socIndex = findSocket(pid, fd, S_ANY);
	if (socIndex == -1){
		this->returnSystemCall(syscallUUID, -1);
	}
	sockaddr_in temp;
	u16 sourcePort = socketList[socIndex].tcpUniqueID.sourcePort;
	u32 sourceIP = socketList[socIndex].tcpUniqueID.sourceIP;
	//printTcpUniqueID(socketList[socIndex].tcpUniqueID);
	*((sockaddr_in *) address) = createSockaddr_in(htons(sourcePort), htonl(sourceIP));
	*((int *) addLength) = sizeof (temp);
	this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd,struct sockaddr* address, socklen_t* addLength){
	//get the des address
	int socIndex = findSocket(pid, fd, S_ANY);
	if (socIndex == -1 && socketList[socIndex].socketState == S_LISTEN){
		this->returnSystemCall(syscallUUID, -1);
	}
	sockaddr_in temp;
	u16 desPort = socketList[socIndex].tcpUniqueID.desPort;
	u32 desIP  = socketList[socIndex].tcpUniqueID.desIP;
	//printTcpUniqueID(socketList[socIndex].tcpUniqueID);
	*((sockaddr_in *) address) = createSockaddr_in(htons(desPort), htonl(desIP));
	*((int *) addLength) = sizeof (temp);
	this->returnSystemCall(syscallUUID, 0);
}

/*
void syscall_close(UUID syscallUUID, int pid, const SystemCallParameter& param);
void syscall_read(UUID syscallUUID, int pid, const SystemCallParameter& param);
void syscall_write(UUID syscallUUID, int pid, const SystemCallParameter& param);
void syscall_connect(UUID syscallUUID, int pid, const SystemCallParameter& param);

void syscall_accept(UUID syscallUUID, int pid, const SystemCallParameter& param);
void syscall_bind(UUID syscallUUID, int pid, const SystemCallParameter& param);*/

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{	
	switch(param.syscallNumber)
	{
	case SOCKET:
		printf("--------------------------SOCKET\n");
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		printf("--------------------------CLOSE\n");
		//this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
	printf("--------------------------READ\n");
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
	printf("--------------------------WRITE\n");
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
	printf("--------------------------CONNECT\n");
		//this->syscall_connect(syscallUUID, pid, param.param1_int,static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		//		
		break;
	case LISTEN:
	printf("--------------------------LISTEN\n");
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
	printf("--------------------------ACCEPT\n");
		this->syscall_accept(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr*>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
	printf("--------------------------BIND\n");
		this->syscall_bind(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr), (socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
	printf("--------------------------GETSOCKNAME\n");
		this->syscall_getsockname(syscallUUID, pid, param.param1_int,
				static_cast<struct sockaddr *>(param.param2_ptr),
				static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
	printf("--------------------------GETPEERNAME\n");
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}



void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	//printf("Packet Arrived\n");
	demArrive++;
	TCPHeader tcpHeader, tempHeader;
	u32 IPStart = 14;
	u32 TCPStart = 14 + 20;

	//Determine sourceIP and desIP
	u8 IPbuf[4];
	packet->readData(26, IPbuf, 4);
	u32 sourceIP = arrayToUINT64_not_inverse(IPbuf, 4);
	packet->readData(30, IPbuf, 4);
	u32 desIP = arrayToUINT64_not_inverse(IPbuf, 4);

	//Extract some information from TCP header
	packet->readData(TCPStart, &tcpHeader, 20);
	u8 dm[20];packet->readData(TCPStart, dm, 20);
	
	//std::cout << "DMDMDM SEQUENCE " << " " <<ntohs(tcpHeader.sequence) << std::endl;
	u16 desPort = ntohs(tcpHeader.desPort);
	u16 sourcePort = ntohs(tcpHeader.sourcePort);
	u8 flag = tcpHeader.flag;
	bool SYN = 1 & (flag >> 1);
	bool ACK = 1 & (flag >> 4);


	
	TcpUniqueID tcpUniqueID;
	tcpUniqueID.sourcePort = desPort;
	tcpUniqueID.sourceIP = desIP;
	tcpUniqueID.desPort = sourcePort;
	tcpUniqueID.desIP = sourceIP;

	//length of data
	u16 dataLength;
	u8 headerLength = (tcpHeader.headerLength) /4;
	u8 totalLengthBuf[2];
	packet->readData(16, totalLengthBuf, 2);
	u16 totalLength = htons(*((u16*)totalLengthBuf));
	dataLength = totalLength - headerLength - 20;
	//if the packet is corrupted
	u8 data[dataLength + 20];

	packet->readData(34, data, dataLength + 20);
  u16 temp;
  if ((temp = findTcpChecksum(htonl(sourceIP), htonl(desIP), data, headerLength + dataLength)) != 0){
  	this->freePacket(packet);
  	return;
  }
 	packet->readData(34 + headerLength, data, dataLength);
	
  
	if (SYN && !ACK){   // Receive only SYN
		int listenSocket = findSocketByAddress(desPort, desIP, S_LISTEN);
		int toBeEstablishedSocketsIndex;
		if (listenSocket != -1){
			toBeEstablishedSocketsIndex = findToBeEstablishedSockets(desPort, desIP);
		}
		//Deny by sending RST.
		//Two cases: cannot find a matched socket or the (port, IP) is full of to-be-established sockets
		if (listenSocket == -1 || toBeEstablishedSocketsIndex == -1){ 
			tempHeader = tcpHeader;
			tempHeader.desPort = tcpHeader.sourcePort;
			tempHeader.sourcePort = tcpHeader.desPort;
			tempHeader.flag = 0x04;	

			Packet* returnPacket = this->clonePacket(packet);
			u32 tempDesIP = htonl(desIP);
			u32 tempSourceIP = htonl(sourceIP);
			returnPacket->writeData(26, &(tempDesIP), 4);
			returnPacket->writeData(30, &(tempSourceIP),  4);
			returnPacket->writeData(TCPStart, &tempHeader, 20);
			this->sendPacket ("IPv4", returnPacket);
			return;
		}
		//Create new socket(toBeEstablished) for this SYN request
		toBeEstablishedSockets myToBeEstablishedSockets = toBeEstablishedList[toBeEstablishedSocketsIndex];
		
		Socket newSocket;
		newSocket.pid = myToBeEstablishedSockets.pid;
		newSocket.fd = this->createFileDescriptor(newSocket.pid);
		// newSocket.tcpUniqueID.sourcePort = myToBeEstablishedSockets.sourcePort;
		// newSocket.tcpUniqueID.sourceIP = myToBeEstablishedSockets.sourceIP;
		// newSocket.tcpUniqueID.desPort = sourcePort;
		// newSocket.tcpUniqueID.desIP = sourceIP;
		newSocket.tcpUniqueID = tcpUniqueID;
		newSocket.socketState = S_SYN_RCVD;
		newSocket.startCanRead = 0;
		newSocket.windowBase = newSocket.startCanRead;
		
		newSocket.receiveBuf = (u8 *) malloc(RECEIVE_BUF_SIZE);
		newSocket.peerBufSize = ntohs(tcpHeader.window);
		newSocket.peerNext = addNum(ntohl(tcpHeader.sequence), 1, newSocket.peerBufSize);
		socketList.push_back(newSocket);
		myToBeEstablishedSockets.socketList.push_back(newSocket.tcpUniqueID);

		//Then sent back SYNACK
		tempHeader = tcpHeader;
		tempHeader.desPort = tcpHeader.sourcePort;
		tempHeader.sourcePort = tcpHeader.desPort;
		tempHeader.flag = 0x12;
		tempHeader.sequence = newSocket.startCanRead;
		tempHeader.acknowledge = htonl(addNum(ntohl(tcpHeader.sequence), 1, newSocket.peerBufSize));
		//std::cout << "------------------------------ "  << tempHeader.acknowledge << std::endl;

		tempHeader.window = RECEIVE_BUF_SIZE;
		tempHeader.checksum = 0;
		tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
		//printf("total checksum to send %hu\n", htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4)));
		u32 tempDesIP = htonl(desIP);
		u32 tempSourceIP = htonl(sourceIP);
		
		Packet* returnPacket = this->clonePacket(packet);
		returnPacket->writeData(26, &(tempDesIP), 4);
		returnPacket->writeData(30, &(tempSourceIP),  4);
		returnPacket->writeData(TCPStart, &tempHeader, 20);

		this->sendPacket ("IPv4", returnPacket);
		return;

	} else if (SYN && ACK){ //SYNACK

	} else if (!SYN && ACK){  //Only an ACK

		int socIndex = findSocketByTCPUniqueID(tcpUniqueID, S_ANY);
		Socket mySocket = socketList[socIndex];
		//if this ACK is for three-way handshake
		if (mySocket.socketState == S_SYN_RCVD) {
			socketList[socIndex].socketState = S_ESTABLISHED;
			//Remove this socket from toBeEstablishedSockets
			int toBeEstablishedSocketsIndex = findToBeEstablishedSockets(desPort, desIP);
			toBeEstablishedSockets myToBeEstablishedSockets = toBeEstablishedList[toBeEstablishedSocketsIndex];
			for (int i = 0; i < (int)myToBeEstablishedSockets.socketList.size(); i++){
				if (sameTcpUniqueID(myToBeEstablishedSockets.socketList[i], tcpUniqueID)){
					myToBeEstablishedSockets.socketList.erase(myToBeEstablishedSockets.socketList.begin() + i);
					break;
				}
			}
			
			//Append this socket to establishedSockets
			int establishedSocketsIndex = findEstablishedSockets(desPort, desIP);
		  establishedList[establishedSocketsIndex].socketList.push_back(tcpUniqueID);
		  
		  //We now have a new established socket. Then check if there is any accept call waiting for an established socket
		  int waitingAcceptSocketIndex = findWaitingAcceptSocket(desPort, desIP);
		  waitingAcceptSocket myWaitingAcceptSocet = waitingAcceptList[waitingAcceptSocketIndex];
		  if (myWaitingAcceptSocet.isWaiting){
		  	//the socket is then not waiting until another accept is invoked
		  	myWaitingAcceptSocet.isWaiting = false;
		  	//Prepare return value
		  	sockaddr_in temp;
		  	*((sockaddr_in *) myWaitingAcceptSocet.address) = createSockaddr_in(htons(sourcePort), htonl(sourceIP));
				*((int *) myWaitingAcceptSocet.addLength) = sizeof (temp);
		  	this->returnSystemCall(myWaitingAcceptSocet.syscallUUID, myWaitingAcceptSocet.fd);
		  }
		}
		
		//If there is data to receive
		if (dataLength > 0){

			u32 sequence = htonl(tcpHeader.sequence);
			//if the packet bigger than current window or is out of order, ignore it and send current peerNext
			if ((u32)dataLength > mySocket.rwnd || sequence != mySocket.peerNext) {
				// if (demArrive < 6) {
				// 	printf("Packet is out of order at time %d\n", demArrive);
				// 	std::cout << "mySocket.rwnd " << " " << mySocket.rwnd << std::endl;
				// 	std::cout << "sequence " << " " << sequence << std::endl;
				// 	std::cout << "mySocket.peerNext " << " " << mySocket.peerNext << std::endl;
				// }
				tempHeader = tcpHeader;
				tempHeader.desPort = tcpHeader.sourcePort;
				tempHeader.sourcePort = tcpHeader.desPort;
				tempHeader.flag = 0x10;
				tempHeader.sequence = tcpHeader.acknowledge;
				tempHeader.acknowledge = mySocket.peerNext; //still want the peerNext
				tempHeader.window = htons(mySocket.rwnd);
				tempHeader.checksum = 0;
				tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
		
				u32 tempDesIP = htonl(desIP);
				u32 tempSourceIP = htonl(sourceIP);

				Packet* returnPacket = this->clonePacket(packet);
				returnPacket->writeData(26, &(tempDesIP), 4);
				returnPacket->writeData(30, &(tempSourceIP),  4);
				returnPacket->writeData(TCPStart, &tempHeader, 20);

				this->sendPacket ("IPv4", returnPacket);
			} else {
				//the packet is in order and <= rwnd
				//copy data to receive buffer
				copyData(data, dataLength, mySocket.receiveBuf, mySocket.windowBase, mySocket.startCanRead);
				mySocket.rwnd -= dataLength;
				socketList[socIndex].rwnd -= dataLength;
				socketList[socIndex].peerNext =  addNum(mySocket.peerNext, dataLength, mySocket.peerBufSize);
				mySocket.windowBase = add(mySocket.windowBase, dataLength);
				//Then sent back ACK
				tempHeader = tcpHeader;
				tempHeader.desPort = tcpHeader.sourcePort;
				tempHeader.sourcePort = tcpHeader.desPort;
				tempHeader.flag = 0x10;
				tempHeader.sequence = tcpHeader.acknowledge;
				tempHeader.acknowledge = htonl(addNum(ntohl(tcpHeader.sequence), (int)dataLength, mySocket.peerBufSize));
				if (demArrive < 6) {
					std::cout << "rwnd " << mySocket.rwnd << std::endl;
					//printf("%\n");
					printf("Packet can be received data Time: %d with dataLength %hu\n", demArrive, dataLength);
				}
				tempHeader.window = htons(mySocket.rwnd);
				tempHeader.checksum = 0;
				tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
				
				u32 tempDesIP = htonl(desIP);
				u32 tempSourceIP = htonl(sourceIP);

				//Packet* returnPacket = this->clonePacket(packet);
				Packet* returnPacket = this->allocatePacket(14 + 20 + 20);
				returnPacket->writeData(26, &(tempDesIP), 4);
				returnPacket->writeData(30, &(tempSourceIP),  4);
				returnPacket->writeData(TCPStart, &tempHeader, 20);
				//printf("Sending times %d\n", demArrive);
				this->sendPacket ("IPv4", returnPacket);

			}	
		} 

	}
	
}

void TCPAssignment::timerCallback(void* payload)
{

}


}
