/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2016. 04. 10.
 *      Author: Cuong Nguyen
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"
#include <string>

namespace E
{
//HELPER FUNCTION
u32 min(u32 a, u32 b){
  if (a < b) return a;
  return b;
}

u32 max(u32 a, u32 b){
  if (a > b) return a;
  return b;
}

int add(u32 a, u32 b){
  return (a + b) % RECEIVE_BUF_SIZE;
}

int minus(u32 a, u32 b){
  if (b <= a) return a - b;
  return RECEIVE_BUF_SIZE - (b - a);
}

int addNum(u32 a, u32 b, u32 base = 0){
  return (a + b);
}

int minusNum(u32 a, u32 b, u32 base){
  if (b <= a) return a - b;
  return base - (b - a);
}

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

void copyBufWrite(u8* buf1, u8* buf2, int length, int startFrom){
  for (int i = 0; i < length; i++){
    int j = add(startFrom, i);
    buf2[j] = buf1[i];
  }
}

void copyBuf(u8* buf1, u8* buf2, int length){
  for (int i = 0; i < length; i++){
    buf2[i] = buf1[i];
  }
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


struct sockaddr_in createSockaddr_in (u16 port, u32 IP) {
  struct sockaddr_in myAddr;
  socklen_t len = sizeof(myAddr);
  memset(&myAddr, 0, len);
  myAddr.sin_family = AF_INET;
  myAddr.sin_port = port;
  myAddr.sin_addr.s_addr = IP;
  return myAddr;    
}

u32 addOneSum1(u32 curSum, u8* buf, int length){
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

u32 addOneSum(u32 curSum, u8* buf, int length){
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

  res = addOneSum(res, (u8*) &sourceIP, 4);
  res = addOneSum(res, (u8*) &desIP, 4);
  res = addOneSum(res, (u8*) &protocol, 2);
  res = addOneSum(res, (u8*) &tempLength, 2);
  res = addOneSum(res, buf, (int)length);

  if (buf1 != NULL && length1 != 0){
    res = addOneSum(res, buf1, (int)length1);
  }
  while (res>>16)
    res = (res & 0xffff) + (res >> 16);

  res = ~res;
  return (u16) res;
}

u16 findCheckSum(u8* buf, int length){
  u32 res = addOneSum(0, buf, length);
  while (res>>16)
    res = (res & 0xffff) + (res >> 16);

  res = ~res;
  return (u16) res; 
}

u32 packetSize(){
  return MSS;
}


void copyData(u8* buf, int length, u8* desBuf, u32* from){
  int j = 0;
  while (length > 0){
    desBuf[*from] = buf[j++];
    *from = add(*from, 1);
    length--;
  }
}


u16 getPort(struct sockaddr_in* address){
  return address->sin_port;
}

u32 getIP(struct sockaddr_in* address){
  return (address->sin_addr).s_addr;
}

void read(u8* buf, u32 length, u8* buf1, u32* startCanRead){
  u32 i = 0;
  while (i < length){
    buf[i] = buf1[*startCanRead];
    *startCanRead = add(*startCanRead, 1);
    i++;
  }
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
  srand (time(NULL));
  isActive = true;
}

void TCPAssignment::finalize()
{
    this->isActive = false;
    socketList.clear();
    toBeEstablishedList.clear();
    establishedList.clear();
    waitingAcceptList.clear();
}

int TCPAssignment::findSocket(int pid, int fd, SocketStates socketState){
  int foundIndex = -1;
  for (int i = 0; i < (int)socketList.size(); i++){
    if (socketList[i].pid == pid && (fd == -1 || socketList[i].fd == fd) && (socketList[i].socketState == socketState || socketState == S_ANY)){
      return i;
    }
  }
  return foundIndex;
}

int TCPAssignment::findSocketByAddress(u16 port, u32 IP, SocketStates socketState){
  for (int i = 0; i < (int)socketList.size(); i++){
    if (samePortAndIP(port, IP, socketList[i].tcpUniqueID.sourcePort, socketList[i].tcpUniqueID.sourceIP) 
        && (socketState == socketList[i].socketState || socketState == S_ANY)){
      return i;
    }
  }
  return -1;
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
    if (samePortAndIP(port, IP, sockets.sourcePort, sockets.sourceIP)) {
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
    if (socketStart <= i)
    if ( tempSoc.fd != sockFd && samePortAndIP(tempPort, tempIP, expectedPort, expectedIP) && tempSoc.isAlreadyBound){
      return false;
    }
  }
  return true;
}

int TCPAssignment::tryToSendPacket(int socIndex, u8* buf, u32 length, bool isForTimeout = false, bool isFastRetransmit = false){
  Socket mySocket = socketList[socIndex];
  u32 window = mySocket.peerWindow;
  u32 cwnd = mySocket.cwnd;

  
  if (mySocket.nextSend + length <= mySocket.firstSending + min(window, cwnd)){
    //Prepare the packet to send
    u32 sourceIP = htonl(mySocket.tcpUniqueID.sourceIP);
    u32 desIP = htonl(mySocket.tcpUniqueID.desIP);

    TCPHeader tempHeader;
    tempHeader.sourcePort = htons(mySocket.tcpUniqueID.sourcePort);
    tempHeader.desPort = htons(mySocket.tcpUniqueID.desPort);
    tempHeader.sequence = htonl(socketList[socIndex].nextSend);
    tempHeader.acknowledge = htonl(mySocket.readyReceive);
    tempHeader.headerLength = 0x50;
    tempHeader.flag = 0x10;
    tempHeader.window = htons(mySocket.rwnd);
    tempHeader.checksum = 0;

    u8* data = (u8 *) malloc(20 + length);
    copyBuf((u8*)&tempHeader, data, 20);
    copyBuf(buf, data + 20, length);

    tempHeader.checksum = htons(findTcpChecksum(sourceIP, desIP, data, 20 + length));
    free(data);
    Packet* sendPacket = this->allocatePacket(34 + 20 + length);
    sendPacket->writeData(26, &sourceIP, 4);
    sendPacket->writeData(30, &desIP,  4);
    sendPacket->writeData(34, &tempHeader, 20);
    sendPacket->writeData(34 + 20, buf, length);

    this->sendPacket ("IPv4", sendPacket);
    
    
    if (!isFastRetransmit && socketList[socIndex].firstSending == socketList[socIndex].nextSend){
      TimerPayload* payload = (struct TimerPayload*) malloc(sizeof(struct TimerPayload));
      payload->socIndex = socIndex;
      Time timeout = SIMPLE_TIME_OUT;
      if (socketList[socIndex].lastRTT != 0){
        timeout = socketList[socIndex].estimatedRTT + 4 * socketList[socIndex].devRTT;
        timeout++;
      }
      if (isForTimeout){
        timeout = socketList[socIndex].currentTimeout * 2;
        socketList[socIndex].currentTimeout = timeout;
      }else {
        socketList[socIndex].currentTimeout = timeout;  
      }
      
      socketList[socIndex].currentTimerId = this->addTimer(payload, timeout);
    }
    //Update the buffer
    socketList[socIndex].nextSend += length;
    return 0;
  } else {
    return -1;
  }
}

int TCPAssignment::tryToFreeSendingBuf(int socIndex, bool freeOnlyFirstMSS = false, bool isForTimeout = false){
  u8* buf = socketList[socIndex].sendBuf;
  int sent = 0;
  while (socketList[socIndex].sendBufLength > 0 
    && (socketList[socIndex].nextSend - socketList[socIndex].firstSending < socketList[socIndex].sendBufLength)){
    u32 remainData = socketList[socIndex].sendBufLength - (socketList[socIndex].nextSend - socketList[socIndex].firstSending);
    u32 sendLength = min(packetSize(), remainData);
    int temp = tryToSendPacket(socIndex, &buf[socketList[socIndex].sendBufHead], sendLength, isForTimeout, freeOnlyFirstMSS);
    if (temp == -1){
      break;
    } else {
      socketList[socIndex].sendTime[socketList[socIndex].sendBufHead]++;
      socketList[socIndex].sendFrom[socketList[socIndex].sendBufHead] = this->getHost()->getNetworkSystem()->getCurrentTime ();
      socketList[socIndex].sendBufHead = add(socketList[socIndex].sendBufHead, sendLength);
      sent += sendLength;
      if (freeOnlyFirstMSS) break;
    }
  }
  return sent;
}

Time TCPAssignment::calculateRTO(int socIndex){
  return (Time) ((1 - ALPHA) * socketList[socIndex].estimatedRTT + ALPHA * socketList[socIndex].lastRTT);
}

Time abs(Time a, Time b){
  if (a > b){
    return a - b;
  }
  return b - a;
}

Time TCPAssignment::calculateDevRTT(int socIndex){
  Socket mySocket = socketList[socIndex];
  return (Time)((1 - BETA) * mySocket.devRTT + BETA * abs(mySocket.lastRTT, mySocket.estimatedRTT));
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int param1, int param2){
  int newFd = this->createFileDescriptor(pid);
  Socket newSocket;
  newSocket.fd = newFd;
  newSocket.pid = pid;
  newSocket.firstSending = 0;//rand();
  newSocket.nextSend = newSocket.firstSending;
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
  Socket mySocket = socketList[socIndex];
  if (mySocket.isAlreadyBound && mySocket.tcpUniqueID.sourceIP == 0 && expectedIP == 0
    && mySocket.tcpUniqueID.sourceIP != expectedPort){
    this->returnSystemCall(syscallUUID, -1); 
    return;
  }
  if (!checkValidBoundAddress(expectedPort,expectedIP,fd)){
    this->returnSystemCall(syscallUUID, -1); 
    return;
  }
  //Start binding
  socketList[socIndex].tcpUniqueID.sourceIP = expectedIP;
  socketList[socIndex].tcpUniqueID.sourcePort = expectedPort;
  socketList[socIndex].isAlreadyBound = true;
  socketList[socIndex].fd = fd;
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog){
  int socIndex = findSocket(pid, -1, S_CLOSED);
  if (socIndex == -1){
    this->returnSystemCall(syscallUUID, -1); 
    return;
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

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr* address, socklen_t addLength){
  u32 expectedIP;
  u16 expectedPort;
  int socIndex = findSocket(pid, -1, S_CLOSED);
  if (socIndex == -1){
    this->returnSystemCall(syscallUUID, -1); 
    return;
  }
  //First bind it if neccessary
  if (!socketList[socIndex].isAlreadyBound) {
    //Choose expected IP and Port
    expectedIP= htonl(INADDR_ANY);
    bool foundPort = false;
    for (u16 i = 0; i < 65536; i++) {
      i = rand() % 65536;
      expectedPort = i;
      if (checkValidBoundAddress(expectedPort, expectedIP, socIndex)){
        foundPort = true;
        break;
      }
    }
    if (!foundPort) {  //No more port available to bind
      this->returnSystemCall(syscallUUID, -1);
      return;
    }
    this->getHost()->getIPAddr((u8 *) &expectedIP , this->getHost()->getRoutingTable((u8 *)&expectedIP));
    //Address of this socket
    expectedIP = htonl(expectedIP);
  } else {
    expectedIP = socketList[socIndex].tcpUniqueID.sourceIP;
    expectedPort = socketList[socIndex].tcpUniqueID.sourcePort;
  }
  socketList[socIndex].tcpUniqueID.sourceIP = expectedIP;
  socketList[socIndex].tcpUniqueID.sourcePort = expectedPort;
  socketList[socIndex].tcpUniqueID.desIP =  ntohl(getIP((sockaddr_in*)address));
  socketList[socIndex].tcpUniqueID.desPort = ntohs(getPort((sockaddr_in*)address));
  socketList[socIndex].isAlreadyBound = true;
  socketList[socIndex].receiveBuf = (u8 *) malloc(SEND_BUF_SIZE);
  u32 tempSourceIP = htonl(socketList[socIndex].tcpUniqueID.sourceIP);
  u32 tempDesIP = htonl(socketList[socIndex].tcpUniqueID.desIP);
  //Start connecting by send SYN
  socketList[socIndex].socketState = S_SYN_SENT;
  

  TCPHeader tempHeader;
  tempHeader.sourcePort = htons(expectedPort);
  tempHeader.desPort = getPort((sockaddr_in*)address);
  tempHeader.sequence = htonl(socketList[socIndex].firstSending);
  tempHeader.acknowledge = 0;
  tempHeader.headerLength = 0x50;
  tempHeader.flag = 0x02;
  tempHeader.window = htons(RECEIVE_BUF_SIZE);
  tempHeader.checksum = 0;

  tempHeader.checksum = htons(findTcpChecksum(tempSourceIP, tempDesIP,(u8*)&tempHeader, 20));

  Packet* sendPacket = this->allocatePacket(34 + 20);
  
  sendPacket->writeData(26, &tempSourceIP, 4);
  sendPacket->writeData(30, &tempDesIP,  4);
  sendPacket->writeData(34, &tempHeader, 20);
  this->sendPacket ("IPv4", sendPacket);
  socketList[socIndex].connectId = syscallUUID;

}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd,struct sockaddr* address, socklen_t* addLength){
  struct sockaddr_in tempAddr;
  *addLength = sizeof(tempAddr);
  //find the calling socket
  int socIndex = findSocket(pid, -1, S_LISTEN);
  if (socIndex == -1){
    this->returnSystemCall(syscallUUID, -1); 
    return;
  }
  u16 sourcePort = socketList[socIndex].tcpUniqueID.sourcePort;
  u32 sourceIP = socketList[socIndex].tcpUniqueID.sourceIP;
  //If there is now at least an etablished socket, then get it
  int establishedSocketsIndex = findEstablishedSockets(sourcePort, sourceIP);
  if (establishedList[establishedSocketsIndex].socketList.size() > 0){
    //Pop out the first established socket
    TcpIDAndFd IDandFd = establishedList[establishedSocketsIndex].socketList[0];
    u16 desPort = establishedList[establishedSocketsIndex].socketList[0].tcpUniqueID.desPort;
    u32 desIP = establishedList[establishedSocketsIndex].socketList[0].tcpUniqueID.desIP;
    establishedList[establishedSocketsIndex].socketList.erase(establishedList[establishedSocketsIndex].socketList.begin());
    //Prepare return value
    tempAddr = createSockaddr_in(htons(desPort), htonl(desIP));
    *((sockaddr_in*)address) = tempAddr;
    this->returnSystemCall(syscallUUID, IDandFd.fd);
  } else {
    //Else just wait until an ACK for three-way handshake is received
    int waitingAcceptIndex = findWaitingAcceptSocket(sourcePort, sourceIP);
    waitingAcceptList[waitingAcceptIndex].isWaiting = true;
    waitingAcceptList[waitingAcceptIndex].syscallUUID = syscallUUID;
    waitingAcceptList[waitingAcceptIndex].address = address;
    waitingAcceptList[waitingAcceptIndex].length = addLength;
  }
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, u8* buf, u32 length){
  int socIndex = findSocket(pid, -1, S_ESTABLISHED);
  if (socIndex == -1){
    this->returnSystemCall(syscallUUID, -1); 
    return;
  }
  u32 startCanRead = socketList[socIndex].startCanRead;
  u32 windowBase = socketList[socIndex].windowBase;
  u32 returnLength = min(minus(windowBase, startCanRead), length);

  //If there is no data in the receive buffer 
  if (returnLength == 0) {
    socketList[socIndex].isWaitingRead = true;
    socketList[socIndex].readId = syscallUUID;
    socketList[socIndex].readBuf = buf;
    socketList[socIndex].readLength = length;
  } else { //Take out data from buffer as much as possible
    read(buf, returnLength, socketList[socIndex].receiveBuf, &socketList[socIndex].startCanRead);
    socketList[socIndex].rwnd += returnLength;
    this->returnSystemCall(syscallUUID, returnLength);
  }
  
}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, u8* buf, u32 length){
  
  int socIndex = findSocket(pid, -1, S_ESTABLISHED);
  u32 sendLength = min(length, SEND_BUF_SIZE);
  if (socIndex == -1){
    this->returnSystemCall(syscallUUID, -1); 
    return;
  }
  //Prepare memory
  if (socketList[socIndex].sendBuf == NULL){
    socketList[socIndex].sendBuf = (u8 *) malloc(SEND_BUF_SIZE);
  }
  socketList[socIndex].hasSend = true;
  if (socketList[socIndex].sendTime == NULL){
    socketList[socIndex].sendTime = (int*) malloc(SEND_BUF_SIZE * sizeof(int*));
    for (int i = 0; i < (int)SEND_BUF_SIZE;i++){
      socketList[socIndex].sendTime[i] = 0;
    }
  }
  if (socketList[socIndex].sendFrom == NULL){
    socketList[socIndex].sendFrom = (Time*) malloc(SEND_BUF_SIZE * sizeof(Time*));
  }

  // If there is enough buffer to hold requested chunk
  if (sendLength <= SEND_BUF_SIZE - socketList[socIndex].sendBufLength){
    socketList[socIndex].sendBufLength += sendLength;
     copyBufWrite(buf, socketList[socIndex].sendBuf, sendLength, socketList[socIndex].sendBufTail);

    socketList[socIndex].sendBufTail = add(socketList[socIndex].sendBufTail, sendLength);
    tryToFreeSendingBuf(socIndex);
    this->returnSystemCall(syscallUUID, sendLength);
  } else {

    //Wait to return when there is enough buffer
    socketList[socIndex].isWaitingWrite = true;
    socketList[socIndex].writeId = syscallUUID;
    socketList[socIndex].writeLength = sendLength;
    socketList[socIndex].writeBuf = buf;
  }
}

void TCPAssignment::lateClose(int socIndex, UUID syscallUUID, int pid, int fd){
  if (socketList[socIndex].socketState == S_LISTEN){
    socketList[socIndex].socketState = S_CLOSED;
    this->returnSystemCall(syscallUUID, 0);
    socketStart++; 
    return;
  }

  Socket mySocket = socketList[socIndex];
  if (mySocket.socketState == S_CLOSED){
    this->removeFileDescriptor(pid, fd);
    this->returnSystemCall(syscallUUID, 0);  
    socketStart++;
    return;
  }
  socketList[socIndex].socketState = S_FIN_WAIT_1;

  TCPHeader tempHeader;
  tempHeader.desPort = htons(mySocket.tcpUniqueID.desPort);
  tempHeader.sourcePort = htons(mySocket.tcpUniqueID.sourcePort);
  tempHeader.flag = 0x01;
  tempHeader.sequence = htonl(socketList[socIndex].nextSend);
  tempHeader.acknowledge = htonl(socketList[socIndex].readyReceive);
  tempHeader.headerLength = 0x50;
  tempHeader.window = htons(socketList[socIndex].rwnd);
  tempHeader.checksum = 0;
  tempHeader.checksum = htons(findTcpChecksum(htonl(mySocket.tcpUniqueID.sourceIP), htonl(mySocket.tcpUniqueID.desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
  u32 sourceIP = htonl(mySocket.tcpUniqueID.sourceIP);
  u32 desIP = htonl(mySocket.tcpUniqueID.desIP);
  Packet* returnPacket = this->allocatePacket(14 + 20 + 20);
  returnPacket->writeData(26, &sourceIP, 4);
  returnPacket->writeData(30, &desIP,  4);
  returnPacket->writeData(14 + 20, &tempHeader, 20);
  this->sendPacket ("IPv4", returnPacket);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int fd){
  int socIndex = findSocket(pid, -1, S_ANY);
  if (socIndex == -1){
    this->returnSystemCall(syscallUUID, -1); 
    return;
  }
  socketList[socIndex].isWaitingClose = true;
  socketList[socIndex].closeId = syscallUUID;
  socketList[socIndex].closePid = pid;
  socketList[socIndex].closeFd = fd;

  if (socketList[socIndex].firstSending == socketList[socIndex].nextSend){
    socketList[socIndex].isWaitingClose = false;
    lateClose(socIndex, socketList[socIndex].closeId, socketList[socIndex].closePid, socketList[socIndex].closeFd);
  }
  
  
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd,struct sockaddr* address, socklen_t* addLength){
  //Get the source address
  int socIndex = findSocket(pid, fd, S_ANY);
  if (socIndex == -1){
    this->returnSystemCall(syscallUUID, -1); 
    return;
  }
  sockaddr_in temp;
  u16 sourcePort = socketList[socIndex].tcpUniqueID.sourcePort;
  u32 sourceIP = socketList[socIndex].tcpUniqueID.sourceIP;
  *((sockaddr_in *) address) = createSockaddr_in(htons(sourcePort), htonl(sourceIP));
  *((int *) addLength) = sizeof (temp);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd,struct sockaddr* address, socklen_t* addLength){
  //get the des address
  int socIndex = findSocket(pid, fd, S_ANY);
  if (socIndex == -1 && socketList[socIndex].socketState == S_LISTEN){
    this->returnSystemCall(syscallUUID, -1); 
    return;
  }
  sockaddr_in temp;
  u16 desPort = socketList[socIndex].tcpUniqueID.desPort;
  u32 desIP  = socketList[socIndex].tcpUniqueID.desIP;
  *((sockaddr_in *) address) = createSockaddr_in(htons(desPort), htonl(desIP));
  *((int *) addLength) = sizeof (temp);
  this->returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{ 
  switch(param.syscallNumber)
  {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, param.param1_int);
    break;
  case READ:
    this->syscall_read(syscallUUID, pid, param.param1_int, (u8*)param.param2_ptr, param.param3_int);
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, param.param1_int, (u8*)param.param2_ptr, param.param3_int);
    break;
  case CONNECT:
    this->syscall_connect(syscallUUID, pid, param.param1_int,static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);  
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
    break;
  case ACCEPT:
    this->syscall_accept(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr*>(param.param2_ptr),
        static_cast<socklen_t*>(param.param3_ptr));
    break;
  case BIND:
    this->syscall_bind(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr), (socklen_t) param.param3_int);
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr *>(param.param2_ptr),
        static_cast<socklen_t*>(param.param3_ptr));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr *>(param.param2_ptr),
        static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}



void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
  if (!isActive){
    this->freePacket(packet);
    return;
  }
  
  TCPHeader tcpHeader, tempHeader;
  //u32 IPStart = 14;
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

  u16 desPort = ntohs(tcpHeader.desPort);
  u16 sourcePort = ntohs(tcpHeader.sourcePort);
  u8 flag = tcpHeader.flag;
  bool SYN = 1 & (flag >> 1);
  bool ACK = 1 & (flag >> 4);
  bool FIN = 1 & (flag);

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
  u8 data[dataLength + headerLength];
  packet->readData(34, data, dataLength + headerLength);
  u16 temp;
  //Check corrupted packet
  if ((temp = findTcpChecksum(htonl(sourceIP), htonl(desIP), data, headerLength + dataLength)) != 0){
    tempHeader = tcpHeader;
    tempHeader.desPort = tcpHeader.sourcePort;
    tempHeader.sourcePort = tcpHeader.desPort;
    tempHeader.flag = 0x10;
    tempHeader.acknowledge = tcpHeader.sequence;
    tempHeader.checksum = 0;
      tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
    Packet* returnPacket = this->clonePacket(packet);
    u32 tempDesIP = htonl(desIP);
    u32 tempSourceIP = htonl(sourceIP);
    returnPacket->writeData(26, &(tempDesIP), 4);
    returnPacket->writeData(30, &(tempSourceIP),  4);
    returnPacket->writeData(TCPStart, &tempHeader, 20);
    this->sendPacket ("IPv4", returnPacket);
    this->freePacket(packet);
    return;
  }
  
  packet->readData(34 + headerLength, data, dataLength); //data length
  
  /*================================================================================
  ===============================  MAIN JOB  =====================================
  ================================================================================*/

  if (FIN){
    int socIndex1 = findSocketByTCPUniqueID(tcpUniqueID, S_ESTABLISHED);
    int socIndex2 = findSocketByTCPUniqueID(tcpUniqueID, S_FIN_WAIT_2);
    int socIndex = -1;
    if (socIndex1 == -1 && socIndex2 == -1){
    	this->freePacket(packet);
      return; //Invalid

    }
    if (socIndex1 != -1) socIndex = socIndex1;
    if (socIndex2 != -1) socIndex = socIndex2;
    //Now we got the correct socIndex
    if (socketList[socIndex].socketState == S_ESTABLISHED){
      //S_STABLISHED state  
      //Send back an ACK and change it to S_CLOSE_WAIT
      tempHeader = tcpHeader;
      tempHeader.desPort = tcpHeader.sourcePort;
      tempHeader.sourcePort = tcpHeader.desPort;
      tempHeader.flag = 0x10;
      tempHeader.sequence = htonl(socketList[socIndex].nextSend); //dont really need
      tempHeader.acknowledge = htonl(addNum(htonl(tcpHeader.sequence), 1));
      tempHeader.headerLength = 0x50;
      tempHeader.window = htons(socketList[socIndex].rwnd);
      tempHeader.checksum = 0;
      tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
      u32 tempDesIP = htonl(desIP);
      u32 tempSourceIP = htonl(sourceIP);
      Packet* returnPacket = this->allocatePacket(14 + 20 + 20);
      returnPacket->writeData(26, &(tempDesIP), 4);
      returnPacket->writeData(30, &(tempSourceIP),  4);
      returnPacket->writeData(TCPStart, &tempHeader, 20);
      this->sendPacket ("IPv4", returnPacket);
      socketList[socIndex].socketState = S_CLOSE_WAIT;

      //3.Send back a FIN and and change it to S_LAST_ACK
      tempHeader = tcpHeader;
      tempHeader.desPort = tcpHeader.sourcePort;
      tempHeader.sourcePort = tcpHeader.desPort;
      tempHeader.flag = 0x01;
      tempHeader.sequence = htonl(socketList[socIndex].nextSend); //dont really need
      tempHeader.acknowledge = htonl(addNum(htonl(tcpHeader.sequence), 1));  //dont really need
      tempHeader.window = htons(socketList[socIndex].rwnd);
      tempHeader.checksum = 0;
      tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
      tempDesIP = htonl(desIP);
      tempSourceIP = htonl(sourceIP);
      Packet* returnPacket1 = this->allocatePacket(14 + 20 + 20);
      returnPacket1->writeData(26, &(tempDesIP), 4);
      returnPacket1->writeData(30, &(tempSourceIP),  4);
      returnPacket1->writeData(TCPStart, &tempHeader, 20);
      this->sendPacket ("IPv4", returnPacket1);
      socketList[socIndex].socketState = S_LAST_ACK;
    } else if (socketList[socIndex].socketState == S_FIN_WAIT_2) {
      //S_FIN_WAIT_2 state
      //Send back an ACK
      tempHeader = tcpHeader;
      tempHeader.desPort = tcpHeader.sourcePort;
      tempHeader.sourcePort = tcpHeader.desPort;
      tempHeader.flag = 0x10;
      tempHeader.sequence = htonl(socketList[socIndex].nextSend); 
      tempHeader.acknowledge = htonl(addNum(htonl(tcpHeader.sequence), 1));  
      tempHeader.window = htons(socketList[socIndex].rwnd);
      tempHeader.checksum = 0;
      tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
      u32 tempDesIP = htonl(desIP);
      u32 tempSourceIP = htonl(sourceIP);
      Packet* returnPacket1 = this->allocatePacket(14 + 20 + 20);
      returnPacket1->writeData(26, &(tempDesIP), 4);
      returnPacket1->writeData(30, &(tempSourceIP),  4);
      returnPacket1->writeData(TCPStart, &tempHeader, 20);
      this->sendPacket ("IPv4", returnPacket1);
      //Time out
      socketList[socIndex].socketState = S_TIME_WAIT;
      //Close after waiting
      TimerPayload* payload = (struct TimerPayload*) malloc(sizeof(struct TimerPayload));
      payload->socIndex = socIndex;
     
      socketList[socIndex].currentTimerId = this->addTimer(payload, TIME_WAIT);

    } else if (socketList[socIndex].socketState == S_FIN_WAIT_1){
      //Fast close (simultaneous close), return an ACK and change to S_CLOSING
      tempHeader = tcpHeader;
      tempHeader.desPort = tcpHeader.sourcePort;
      tempHeader.sourcePort = tcpHeader.desPort;
      tempHeader.flag = 0x10;
      tempHeader.sequence = htonl(socketList[socIndex].nextSend); 
      tempHeader.acknowledge = htonl(addNum(htonl(tcpHeader.sequence), 1));  
      tempHeader.window = htons(socketList[socIndex].rwnd);
      tempHeader.checksum = 0;
      tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
      u32 tempDesIP = htonl(desIP);
      u32 tempSourceIP = htonl(sourceIP);
      Packet* returnPacket1 = this->allocatePacket(14 + 20 + 20);
      returnPacket1->writeData(26, &(tempDesIP), 4);
      returnPacket1->writeData(30, &(tempSourceIP),  4);
      returnPacket1->writeData(TCPStart, &tempHeader, 20);
      this->sendPacket ("IPv4", returnPacket1);
      socketList[socIndex].socketState = S_CLOSING;
    }
    //Receive FIN  // Receive FIN
  } else if (SYN && !ACK){   // Receive only SYN
    int listenSocket = findSocketByAddress(desPort, desIP, S_LISTEN);
    int sentSynSocket = findSocketByAddress(desPort, desIP, S_SYN_SENT);
    int toBeEstablishedSocketsIndex = -1;

    //if the socket is just sent SYN (part of three-way-hand shake in client side)
    if (sentSynSocket != -1){
      socketList[sentSynSocket].threeWayHandShake++;
      if (socketList[sentSynSocket].threeWayHandShake == 2){
        //Finished three way handshake
        socketList[sentSynSocket].socketState = S_ESTABLISHED;
        socketList[sentSynSocket].readyReceive = ntohl(tcpHeader.sequence) + 1;
        socketList[sentSynSocket].peerWindow = ntohs(tcpHeader.window);
        //Send back ACK
        tempHeader = tcpHeader;
        tempHeader.desPort = tcpHeader.sourcePort;
        tempHeader.sourcePort = tcpHeader.desPort;
        tempHeader.flag = 0x10;
        tempHeader.sequence = ntohl(socketList[sentSynSocket].firstSending);
        tempHeader.acknowledge = ntohl(addNum(ntohl(tcpHeader.sequence), 1));

        tempHeader.window = htons(RECEIVE_BUF_SIZE);
        tempHeader.checksum = 0;
        tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
        
        u32 tempDesIP = htonl(desIP);
        u32 tempSourceIP = htonl(sourceIP);
        
        Packet* returnPacket = this->clonePacket(packet);
        returnPacket->writeData(26, &(tempDesIP), 4);
        returnPacket->writeData(30, &(tempSourceIP),  4);
        returnPacket->writeData(TCPStart, &tempHeader, 20);

        this->sendPacket ("IPv4", returnPacket);
        this->returnSystemCall(socketList[sentSynSocket].connectId, 0);
        this->freePacket(packet);
        return;
      }
      this->freePacket(packet);
      return;
    }

    if (listenSocket != -1){ //If SYN is sent to a listening socket
      toBeEstablishedSocketsIndex = findToBeEstablishedSockets(desPort, desIP);
    }

    //Deny by sending RST.
    //Two cases: cannot find a matched socket or the (port, IP) is full of to-be-established sockets
    int index = toBeEstablishedSocketsIndex;
    
    bool isFull = false;
    if (index == -1){
      isFull = true;
    } else {
      isFull = (int)toBeEstablishedList[index].socketList.size() >= toBeEstablishedList[index].backlog;
    }
    if (listenSocket == -1 || isFull){ 
      tempHeader = tcpHeader;
      tempHeader.desPort = tcpHeader.sourcePort;
      tempHeader.sourcePort = tcpHeader.desPort;
      tempHeader.flag = 0x04; 
      tempHeader.checksum = 0;
      tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
      Packet* returnPacket = this->clonePacket(packet);
      u32 tempDesIP = htonl(desIP);
      u32 tempSourceIP = htonl(sourceIP);
      returnPacket->writeData(26, &(tempDesIP), 4);
      returnPacket->writeData(30, &(tempSourceIP),  4);
      returnPacket->writeData(TCPStart, &tempHeader, 20);
      this->sendPacket ("IPv4", returnPacket);
      this->freePacket(packet);
      return;
    }

    //Create new socket(toBeEstablished) for this SYN request
    toBeEstablishedSockets myToBeEstablishedSockets = toBeEstablishedList[toBeEstablishedSocketsIndex];
    
    Socket newSocket;
    newSocket.pid = myToBeEstablishedSockets.pid;
    newSocket.fd = this->createFileDescriptor(newSocket.pid);
    newSocket.tcpUniqueID = tcpUniqueID;
    newSocket.socketState = S_SYN_RCVD;
    newSocket.startCanRead = 0;
    newSocket.windowBase = newSocket.startCanRead;
    
    newSocket.receiveBuf = (u8 *) malloc(RECEIVE_BUF_SIZE);
    newSocket.peerWindow = ntohs(tcpHeader.window);
    newSocket.readyReceive = addNum(ntohl(tcpHeader.sequence), 1);
    newSocket.firstSending =  0;//rand() % 100000;
    newSocket.nextSend = newSocket.firstSending;
    socketList.push_back(newSocket);
    toBeEstablishedList[toBeEstablishedSocketsIndex].socketList.push_back(newSocket.tcpUniqueID);

    //Then sent back SYNACK
    tempHeader = tcpHeader;
    tempHeader.desPort = tcpHeader.sourcePort;
    tempHeader.sourcePort = tcpHeader.desPort;
    tempHeader.flag = 0x12;
    tempHeader.sequence = htonl(newSocket.firstSending);
    tempHeader.acknowledge = ntohl(addNum(ntohl(tcpHeader.sequence), 1));
    tempHeader.window = htons(RECEIVE_BUF_SIZE);
    tempHeader.checksum = 0;
    tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
    
    u32 tempDesIP = htonl(desIP);
    u32 tempSourceIP = htonl(sourceIP);
    
    Packet* returnPacket = this->clonePacket(packet);
    returnPacket->writeData(26, &(tempDesIP), 4);
    returnPacket->writeData(30, &(tempSourceIP),  4);
    returnPacket->writeData(TCPStart, &tempHeader, 20);
    this->sendPacket ("IPv4", returnPacket);
    this->freePacket(packet);
    return;
  } else if (SYN && ACK){ // Receive SYNACK

    int socIndex = findSocketByTCPUniqueID(tcpUniqueID, S_SYN_SENT);
    if (socIndex == -1) {
    	this->freePacket(packet);
    	return;
    }
    socketList[socIndex].socketState = S_ESTABLISHED;
    socketList[socIndex].peerWindow = htons(tcpHeader.window);
    socketList[socIndex].readyReceive = htonl(tcpHeader.sequence) + 1;
    socketList[socIndex].firstSending = htonl(tcpHeader.acknowledge);

    socketList[socIndex].nextSend = htonl(tcpHeader.acknowledge);
    
    //Send back ACK
    this->returnSystemCall(socketList[socIndex].connectId, 0);
    tempHeader = tcpHeader;
    tempHeader.desPort = tcpHeader.sourcePort;
    tempHeader.sourcePort = tcpHeader.desPort;
    tempHeader.flag = 0x10;
    tempHeader.sequence = tcpHeader.acknowledge;
    tempHeader.acknowledge = htonl(addNum(htonl(tcpHeader.sequence), 1));
    tempHeader.headerLength = 0x50;
    tempHeader.window = htons(socketList[socIndex].rwnd);
    tempHeader.checksum = 0;
    tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));

    u32 tempDesIP = htonl(desIP);
    u32 tempSourceIP = htonl(sourceIP);

    Packet* returnPacket = this->allocatePacket(14 + 20 + 20);
    returnPacket->writeData(26, &(tempDesIP), 4);
    returnPacket->writeData(30, &(tempSourceIP),  4);
    returnPacket->writeData(TCPStart, &tempHeader, 20);

    this->sendPacket ("IPv4", returnPacket);
  } else if (!SYN && ACK){  // Receive only an ACK
    //First priority: ACK for LAST_ACK state
    int lastAckSocket = findSocketByTCPUniqueID(tcpUniqueID, S_LAST_ACK);
    if (lastAckSocket != -1){
      //CLOSE EVERYTHING !
      int closeId = socketList[lastAckSocket].closeId;
      socketList[lastAckSocket].socketState = S_CLOSED;
      socketStart++;
      this->returnSystemCall(closeId, 0);
      this->freePacket(packet);
      return;
    }
    //Also first priority: ACK for FIN_WAIT_1
    int finWait1Socket = findSocketByTCPUniqueID(tcpUniqueID, S_FIN_WAIT_1);
    
    if (finWait1Socket != -1){
      socketList[finWait1Socket].socketState = S_FIN_WAIT_2;
      this->freePacket(packet);
      return;
    }
    //Also first priority: ACK for S_CLOSING
    int closingSocket = findSocketByTCPUniqueID(tcpUniqueID, S_CLOSING);
    if (closingSocket != -1){
      socketList[closingSocket].socketState = S_TIME_WAIT;
      TimerPayload* payload = (struct TimerPayload*) malloc(sizeof(struct TimerPayload));
      payload->socIndex = closingSocket;      
      socketList[closingSocket].currentTimerId = this->addTimer(payload, TIME_WAIT);
      this->freePacket(packet);
      return;
    }

    int sentSynSocket = findSocketByAddress(desPort, desIP, S_SYN_SENT);
    bool finishedThreeWay = true;
    //If it is an ACK in SYNACK of three-way handshake
    if (sentSynSocket != -1 && socketList[sentSynSocket].threeWayHandShake < 2){
      finishedThreeWay = false;
      socketList[sentSynSocket].threeWayHandShake++;
      socketList[sentSynSocket].peerWindow = htons(tcpHeader.window);
      if (socketList[sentSynSocket].threeWayHandShake == 2){
        socketList[sentSynSocket].socketState = S_ESTABLISHED;
        if (socketList[sentSynSocket].threeWayHandShake == 2){
          //Finished three way handshake
          socketList[sentSynSocket].socketState = S_ESTABLISHED;
          socketList[sentSynSocket].firstSending = ntohl(tcpHeader.acknowledge);
          socketList[sentSynSocket].nextSend = ntohl(tcpHeader.acknowledge);
          socketList[sentSynSocket].readyReceive = ntohl(tcpHeader.sequence) + 1;
          
          //Send back ACK
          tempHeader = tcpHeader;
          tempHeader.desPort = tcpHeader.sourcePort;
          tempHeader.sourcePort = tcpHeader.desPort;
          tempHeader.flag = 0x10;
          tempHeader.sequence = ntohl(socketList[sentSynSocket].firstSending);
          tempHeader.acknowledge = ntohl(addNum(ntohl(tcpHeader.sequence),0));
          tempHeader.window = htons(RECEIVE_BUF_SIZE);
          tempHeader.checksum = 0;
          tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
          
          u32 tempDesIP = htonl(desIP);
          u32 tempSourceIP = htonl(sourceIP);
          
          Packet* returnPacket = this->clonePacket(packet);
          returnPacket->writeData(26, &(tempDesIP), 4);
          returnPacket->writeData(30, &(tempSourceIP),  4);
          returnPacket->writeData(TCPStart, &tempHeader, 20);

          this->sendPacket ("IPv4", returnPacket);
          this->returnSystemCall(socketList[sentSynSocket].connectId, 0);
          this->freePacket(packet);
          return;
        }
      }
      this->freePacket(packet);
      return;
    }

    int socIndex = findSocketByTCPUniqueID(tcpUniqueID, S_ANY);
    if (socIndex == -1) {
    	this->freePacket(packet);
    	return;
    }
    socketList[socIndex].peerWindow = htons(tcpHeader.window);
    
    Socket mySocket = socketList[socIndex];
    //If this is the last ACK is for three-way handshake (not ACK in SYNACK)
    if (mySocket.socketState == S_SYN_RCVD) {
      finishedThreeWay = false;
      socketList[socIndex].socketState = S_ESTABLISHED;
      socketList[socIndex].firstSending = htonl(tcpHeader.acknowledge);
      socketList[socIndex].nextSend = socketList[socIndex].firstSending;
      //Remove this socket from toBeEstablishedSockets
      int toBeEstablishedSocketsIndex = findToBeEstablishedSockets(desPort, desIP);
      toBeEstablishedSockets myToBeEstablishedSockets = toBeEstablishedList[toBeEstablishedSocketsIndex];
      for (int i = 0; i < (int)myToBeEstablishedSockets.socketList.size(); i++){
        if (sameTcpUniqueID(myToBeEstablishedSockets.socketList[i], tcpUniqueID)){
          toBeEstablishedList[toBeEstablishedSocketsIndex].socketList.erase(toBeEstablishedList[toBeEstablishedSocketsIndex].socketList.begin() + i);
          break;
        }
      }
      //Append this socket to establishedSockets
      int establishedSocketsIndex = findEstablishedSockets(desPort, desIP);
      TcpIDAndFd tempIDandFd;
      tempIDandFd.fd = socketList[socIndex].fd;
      tempIDandFd.tcpUniqueID = tcpUniqueID;
      establishedList[establishedSocketsIndex].socketList.push_back(tempIDandFd);
      //We now have a new established socket. Then check if there is any accept call waiting for an established socket
      int waitingAcceptSocketIndex = findWaitingAcceptSocket(desPort, desIP);
      waitingAcceptSocket myWaitingAcceptSocet = waitingAcceptList[waitingAcceptSocketIndex];
      
      if (myWaitingAcceptSocet.isWaiting){
        //the socket is then not waiting until another accept is invoked
        myWaitingAcceptSocet.isWaiting = false;
        //Pop out the first established socket
        establishedList[establishedSocketsIndex].socketList.erase(establishedList[establishedSocketsIndex].socketList.begin());
        //Prepare return value
        struct sockaddr_in tempAddr = createSockaddr_in(htons(sourcePort), htonl(sourceIP));
        *((sockaddr_in*)(myWaitingAcceptSocet.address)) = tempAddr;

        int newIndex = findSocketByTCPUniqueID(tcpUniqueID, S_ESTABLISHED);
        this->returnSystemCall(myWaitingAcceptSocet.syscallUUID, socketList[newIndex].fd);
      }
    }

    //If there is data to receive
    if (dataLength > 0){
      u32 sequence = htonl(tcpHeader.sequence);
      //If the packet bigger than current window or is out of order, ignore it and still want the readyReceive
      if ((u32)dataLength > mySocket.rwnd || sequence != mySocket.readyReceive) {
        tempHeader = tcpHeader;
        tempHeader.desPort = tcpHeader.sourcePort;
        tempHeader.sourcePort = tcpHeader.desPort;
        tempHeader.flag = 0x10;
        tempHeader.sequence = tcpHeader.acknowledge;
        tempHeader.acknowledge = mySocket.readyReceive; //still want the readyReceive
        tempHeader.headerLength = 0x50;
        tempHeader.window = htons(mySocket.rwnd);
        tempHeader.checksum = 0;
        tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
    
        u32 tempDesIP = htonl(desIP);
        u32 tempSourceIP = htonl(sourceIP);

        Packet* returnPacket = this->allocatePacket(14 + 20 + 20);
        returnPacket->writeData(26, &(tempDesIP), 4);
        returnPacket->writeData(30, &(tempSourceIP),  4);
        returnPacket->writeData(TCPStart, &tempHeader, 20);

        this->sendPacket ("IPv4", returnPacket);
      } else {
        //The packet is in order and <= rwnd
        //Copy data to receive buffer
        copyData(data, dataLength, mySocket.receiveBuf, &socketList[socIndex].windowBase);
        socketList[socIndex].rwnd -= dataLength;
        socketList[socIndex].readyReceive =  addNum(mySocket.readyReceive, dataLength);

        //Free part of buffer if the socket is waiting read
        u32 startCanRead = socketList[socIndex].startCanRead;
        u32 windowBase = socketList[socIndex].windowBase;
        u32 returnLength = min(minus(windowBase, startCanRead), socketList[socIndex].readLength);
        if (returnLength > 0) {
          //Take out (returnLength) bytes from buffer
          read(socketList[socIndex].readBuf, returnLength, socketList[socIndex].receiveBuf, &socketList[socIndex].startCanRead);
          socketList[socIndex].rwnd += returnLength;
          socketList[socIndex].isWaitingRead = false;
          this->returnSystemCall(socketList[socIndex].readId, returnLength);
        }
        mySocket.windowBase = add(mySocket.windowBase, dataLength);
        //Then sent back ACK
        tempHeader = tcpHeader;
        tempHeader.desPort = tcpHeader.sourcePort;
        tempHeader.sourcePort = tcpHeader.desPort;
        tempHeader.flag = 0x10;
        tempHeader.sequence = tcpHeader.acknowledge;
        tempHeader.acknowledge = htonl(addNum(ntohl(tcpHeader.sequence),dataLength));
        tempHeader.headerLength = 0x50;

        tempHeader.window = htons(socketList[socIndex].rwnd);
        tempHeader.checksum = 0;
        tempHeader.checksum = htons(findTcpChecksum(htonl(sourceIP), htonl(desIP), (u8*)&tempHeader, tempHeader.headerLength / 4));
        
        u32 tempDesIP = htonl(desIP);
        u32 tempSourceIP = htonl(sourceIP);

        Packet* returnPacket = this->allocatePacket(14 + 20 + 20);
        returnPacket->writeData(26, &(tempDesIP), 4);
        returnPacket->writeData(30, &(tempSourceIP),  4);
        returnPacket->writeData(TCPStart, &tempHeader, 20);
        this->sendPacket ("IPv4", returnPacket);

      } 
    }
    //If this ACK is acknowleging something
    u32 acknowledge = htonl(tcpHeader.acknowledge);
    bool weird = false;
    if (socketList[socIndex].nextSend + MSS < acknowledge){
      //Not dup
      socketList[socIndex].dupACKcount = 0;

      //RTO
      int startPos = minus(socketList[socIndex].sendBufHead, (socketList[socIndex].nextSend - socketList[socIndex].firstSending));
      int currentPos = minus(add(startPos, acknowledge - mySocket.firstSending),MSS);     
      if (socketList[socIndex].hasSend && socketList[socIndex].sendTime[currentPos] == 1){
        socketList[socIndex].lastRTT = this->getHost()->getNetworkSystem()->getCurrentTime () - socketList[socIndex].sendFrom[currentPos];
        if (socketList[socIndex].estimatedRTT == 0){
          socketList[socIndex].estimatedRTT = socketList[socIndex].lastRTT;
        } else {
          socketList[socIndex].estimatedRTT = calculateRTO(socIndex);
          socketList[socIndex].devRTT = calculateDevRTT(socIndex);
        }
      }

      /*BEGIN TIMER*/
      this->cancelTimer(socketList[socIndex].currentTimerId);
      //There are on-fly bytes
      if (socketList[socIndex].nextSend > acknowledge){
        TimerPayload* payload = (struct TimerPayload*) malloc(sizeof(struct TimerPayload));
        payload->socIndex = socIndex;
        Time timeout = SIMPLE_TIME_OUT;
        if (socketList[socIndex].lastRTT != 0){
          timeout = socketList[socIndex].estimatedRTT + 4 * socketList[socIndex].devRTT;
          timeout++;
        }
        socketList[socIndex].currentTimeout = timeout;        
        socketList[socIndex].currentTimerId = this->addTimer(payload, timeout);
      }
      
      /*END TIMER*/
      weird = true;
      socketList[socIndex].sendBufLength -= (acknowledge - socketList[socIndex].firstSending);
      for (int i = 0; i < (int)(acknowledge - socketList[socIndex].firstSending); i++){
        socketList[socIndex].sendTime[startPos + i] = 0;
      }
      //Adjust sendbuf head
      if (socketList[socIndex].nextSend - socketList[socIndex].firstSending < acknowledge - socketList[socIndex].firstSending){
        socketList[socIndex].sendBufHead = add(socketList[socIndex].sendBufHead, acknowledge - socketList[socIndex].nextSend);
      }

      socketList[socIndex].nextSend = acknowledge;
      socketList[socIndex].firstSending = acknowledge;

    }
    
    socketList[socIndex].peerWindow = htons(tcpHeader.window);

    if (acknowledge >= socketList[socIndex].firstSending && acknowledge <= socketList[socIndex].firstSending + MSS){
      //Duplicate ACK event
      if (!weird){
        if (acknowledge == socketList[socIndex].firstSending){
          if (socketList[socIndex].congestionState == C_SLOW_START){
            //Remain state
            socketList[socIndex].dupACKcount++;
          } else if (socketList[socIndex].congestionState == C_CONGESTION_AVOIDANCE)  { 
            //Remain state
              socketList[socIndex].dupACKcount++;
          } else if (socketList[socIndex].congestionState == C_FAST_RECOVERY){
            //Remain state
            socketList[socIndex].cwnd += MSS;
            tryToFreeSendingBuf(socIndex);
          }
        } else {
          socketList[socIndex].dupACKcount = 0;
        }
   
        //dupACKcount == 3 event
        if (socketList[socIndex].dupACKcount == 3){
          if (socketList[socIndex].congestionState == C_SLOW_START){
            //New state
            socketList[socIndex].congestionState = C_FAST_RECOVERY;
            socketList[socIndex].ssthresh = max(MSS,socketList[socIndex].cwnd / 2);
            socketList[socIndex].cwnd = socketList[socIndex].ssthresh + 3 * MSS;
            u32 savedSendBufHead = socketList[socIndex].sendBufHead;
            u32 savedNextSend = socketList[socIndex].nextSend;
            socketList[socIndex].sendBufHead = minus(mySocket.sendBufHead, mySocket.nextSend - mySocket.firstSending);
            socketList[socIndex].nextSend = socketList[socIndex].firstSending;
            tryToFreeSendingBuf(socIndex, true); //Resend only the first sending 
            socketList[socIndex].sendBufHead = savedSendBufHead;
            socketList[socIndex].nextSend = savedNextSend;
          } else if (socketList[socIndex].congestionState == C_CONGESTION_AVOIDANCE)  { 
            //New state
            socketList[socIndex].congestionState = C_FAST_RECOVERY;
            socketList[socIndex].ssthresh = max(MSS,socketList[socIndex].cwnd / 2);
            socketList[socIndex].cwnd = socketList[socIndex].ssthresh + 3 * MSS;
            u32 savedSendBufHead = socketList[socIndex].sendBufHead;
            u32 savedNextSend = socketList[socIndex].nextSend;
            socketList[socIndex].sendBufHead = minus(mySocket.sendBufHead, mySocket.nextSend - mySocket.firstSending);
            socketList[socIndex].nextSend = socketList[socIndex].firstSending;
            tryToFreeSendingBuf(socIndex, true); //Resend only the first sending 
            socketList[socIndex].sendBufHead = savedSendBufHead;
            socketList[socIndex].nextSend = savedNextSend;
          }
        }
      }
      
  
      // new ACK event
      if (finishedThreeWay && acknowledge > socketList[socIndex].firstSending && acknowledge <= socketList[socIndex].firstSending + MSS){
        int startSendPos = minus(mySocket.sendBufHead, mySocket.nextSend - mySocket.firstSending);
        if (socketList[socIndex].hasSend && socketList[socIndex].sendTime[startSendPos] == 1){
          socketList[socIndex].lastRTT = this->getHost()->getNetworkSystem()->getCurrentTime () - socketList[socIndex].sendFrom[startSendPos];
          if (socketList[socIndex].estimatedRTT == 0){
            socketList[socIndex].estimatedRTT = socketList[socIndex].lastRTT;
          } else {
            socketList[socIndex].estimatedRTT = calculateRTO(socIndex);
            socketList[socIndex].devRTT = calculateDevRTT(socIndex);
          }
        }

        //Create more space in the sending buffer
        //Free the firstSending
        socketList[socIndex].sendTime[startSendPos] = 0;
        socketList[socIndex].sendBufLength -= (acknowledge - socketList[socIndex].firstSending);
        socketList[socIndex].firstSending = acknowledge;
        
        //If all on-fly packets are already sent (deal with Timer)
        if (socketList[socIndex].firstSending == socketList[socIndex].nextSend){
          this->cancelTimer(socketList[socIndex].currentTimerId);
        } else {
          this->cancelTimer(socketList[socIndex].currentTimerId);
          TimerPayload* payload = (struct TimerPayload*) malloc(sizeof(struct TimerPayload));
          payload->socIndex = socIndex;
          Time timeout = SIMPLE_TIME_OUT;
          if (socketList[socIndex].lastRTT != 0){
            timeout = socketList[socIndex].estimatedRTT + 4 * socketList[socIndex].devRTT;
            timeout++;
          }
          socketList[socIndex].currentTimeout = timeout;        
          
          socketList[socIndex].currentTimerId = this->addTimer(payload, timeout);
        }

        if (socketList[socIndex].congestionState == C_SLOW_START){
          //Remain state
          socketList[socIndex].cwnd += MSS;
          socketList[socIndex].dupACKcount = 0;
          tryToFreeSendingBuf(socIndex);
          if (socketList[socIndex].cwnd >= socketList[socIndex].ssthresh){
            socketList[socIndex].congestionState = C_CONGESTION_AVOIDANCE;
          }
        } else if (socketList[socIndex].congestionState == C_CONGESTION_AVOIDANCE)  { 
          //Remain state
          socketList[socIndex].dupACKcount = 0;
          socketList[socIndex].cwnd += MSS / (socketList[socIndex].cwnd / MSS);
          tryToFreeSendingBuf(socIndex);
        } else if (socketList[socIndex].congestionState == C_FAST_RECOVERY){
          //New state
          socketList[socIndex].congestionState = C_CONGESTION_AVOIDANCE;
          socketList[socIndex].cwnd = socketList[socIndex].ssthresh;
          socketList[socIndex].dupACKcount = 0;       
        }
        
        //-------------------        
        if (socketList[socIndex].isWaitingClose && socketList[socIndex].firstSending == socketList[socIndex].nextSend){
          socketList[socIndex].isWaitingClose = false;
          lateClose(socIndex, socketList[socIndex].closeId, socketList[socIndex].closePid, socketList[socIndex].closeFd);
        }

      } else if (weird){
        //Deal with cwnd
        if (socketList[socIndex].congestionState == C_SLOW_START){
          //Remain state
          socketList[socIndex].cwnd += MSS;
          socketList[socIndex].dupACKcount = 0;
          tryToFreeSendingBuf(socIndex);

          if (socketList[socIndex].cwnd >= socketList[socIndex].ssthresh){
            socketList[socIndex].congestionState = C_CONGESTION_AVOIDANCE;
          }
        } else if (socketList[socIndex].congestionState == C_CONGESTION_AVOIDANCE)  { 
          //Remain state
          socketList[socIndex].dupACKcount = 0;
          socketList[socIndex].cwnd += MSS / (socketList[socIndex].cwnd / MSS);
          tryToFreeSendingBuf(socIndex);
        } else if (socketList[socIndex].congestionState == C_FAST_RECOVERY){
          //New state
          socketList[socIndex].congestionState = C_CONGESTION_AVOIDANCE;
          socketList[socIndex].cwnd = socketList[socIndex].ssthresh;
          socketList[socIndex].dupACKcount = 0;       
        }
        if (socketList[socIndex].isWaitingClose && socketList[socIndex].firstSending == socketList[socIndex].nextSend){
          socketList[socIndex].isWaitingClose = false;
          lateClose(socIndex, socketList[socIndex].closeId, socketList[socIndex].closePid, socketList[socIndex].closeFd);
        }
      }
      //Then unblock write function if possible
      if (socketList[socIndex].isWaitingWrite
      && socketList[socIndex].sendBufLength + socketList[socIndex].writeLength <= SEND_BUF_SIZE){
        //Append the requested chunk to the buffer, send and return immediately
        socketList[socIndex].sendBufLength += socketList[socIndex].writeLength;          
        copyBufWrite(socketList[socIndex].writeBuf, socketList[socIndex].sendBuf, socketList[socIndex].writeLength, socketList[socIndex].sendBufTail);
        socketList[socIndex].sendBufTail = add(socketList[socIndex].sendBufTail, socketList[socIndex].writeLength);
        socketList[socIndex].isWaitingWrite = false;
        this->returnSystemCall(socketList[socIndex].writeId, socketList[socIndex].writeLength);  
      }
      tryToFreeSendingBuf(socIndex);
      //////END
    } 
  }
  this->freePacket(packet); 
}

void TCPAssignment::timerCallback(void* payload)
{ 
  struct TimerPayload* message = (struct TimerPayload*) payload;
  int socIndex = message->socIndex;
  Socket mySocket = socketList[socIndex];
  //0.Deal with S_TIME_WAIT
  if (mySocket.socketState == S_TIME_WAIT){
    socketList[socIndex].socketState  = S_CLOSED;
    if (socketList[socIndex].receiveBuf) free(socketList[socIndex].receiveBuf);
    socketList[socIndex].receiveBuf = NULL;
    if (socketList[socIndex].sendBuf) free(socketList[socIndex].sendBuf);
    socketList[socIndex].sendBuf = NULL;
    if (socketList[socIndex].sendTime) free(socketList[socIndex].sendTime);
    socketList[socIndex].sendTime = NULL;
    if (socketList[socIndex].sendFrom) free(socketList[socIndex].sendFrom);
    socketList[socIndex].sendFrom = NULL;
    this->removeFileDescriptor(socketList[socIndex].pid, socketList[socIndex].fd);
    free(message);
    return;
  }

  //1.Deal with congestion control
  socketList[socIndex].ssthresh = max(MSS,socketList[socIndex].cwnd / 2);       //////////////////////////////////
  socketList[socIndex].cwnd = MSS;                                              //Same for all congestion states//
  socketList[socIndex].dupACKcount = 0;                                         //////////////////////////////////
  
  if (socketList[socIndex].congestionState == C_SLOW_START){
    //Remain state
  } else if (socketList[socIndex].congestionState == C_CONGESTION_AVOIDANCE)  { 
    //New state
    socketList[socIndex].congestionState = C_SLOW_START;
  } else if (socketList[socIndex].congestionState == C_FAST_RECOVERY){
    socketList[socIndex].congestionState = C_SLOW_START;
  }

  //2. Retransmit
  this->cancelTimer(socketList[socIndex].currentTimerId);
  socketList[socIndex].sendBufHead = minus(mySocket.sendBufHead, mySocket.nextSend - mySocket.firstSending);
  socketList[socIndex].nextSend = socketList[socIndex].firstSending;
  tryToFreeSendingBuf(socIndex, false, true);
  free(message);
}
}