/*
 * testcongestion.cpp
 *
 *  Created on: 2015. 3. 16.
 *      Author: 근홍
 */

#include <E/E_Common.hpp>
#include <E/E_Module.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Hub.hpp>
#include <E/Networking/Ethernet/E_Ethernet.hpp>
#include <E/Networking/IPv4/E_IPv4.hpp>
#include <E/Networking/TCP/E_TCPApplication.hpp>
#include <E/Networking/TCP/E_TCPSolution.hpp>
#include <E/E_TimeUtil.hpp>
#include <string>

#include <arpa/inet.h>

#include <gtest/gtest.h>
#include "testenv.hpp"

extern "C"
{
#include <stdlib.h>
#include <time.h>
}

using namespace E;

template <typename T>
std::string NumberToString ( T Number )
{
  std::stringstream ss;
  ss << Number;
  return ss.str();
}

class TestCongestion_Accept : public SystemCallApplication, private TCPApplication
{

protected:
  
  std::unordered_map<std::string, std::string> env;
public:
  static int processNumber;
  TestCongestion_Accept(Host* host, const std::unordered_map<std::string, std::string> &env) : SystemCallApplication(host), TCPApplication(this)
{
    this->env = env;
    
}

protected:
  void E_Main()
  {
    
    int connection_timeout = atoi(env["CONNECTION_TIMEOUT"].c_str());
    int server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    memset(&addr, 0, len);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(env["LISTEN_ADDR"].c_str());
    addr.sin_port = htons(atoi(env["LISTEN_PORT"].c_str()));

    int ret = bind(server_socket, (struct sockaddr*)&addr, len);
    EXPECT_EQ(ret, 0);

    long listen_time = atol(env["LISTEN_TIME"].c_str());
    usleep(listen_time);

    ret = listen(server_socket, atoi(env["BACKLOG"].c_str()));
    EXPECT_EQ(ret, 0);

    long accept_time = atol(env["ACCEPT_TIME"].c_str());
    usleep(accept_time);

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    memset(&client_addr, 0, client_len);
    int client_fd = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
    EXPECT_GE(client_fd, 0);

    EXPECT_EQ(client_len, sizeof(client_addr));
    EXPECT_EQ(client_addr.sin_family, AF_INET);

    struct sockaddr_in temp_addr;
    socklen_t temp_len = sizeof(temp_addr);
    ret = getsockname(client_fd, (struct sockaddr*)&temp_addr, &temp_len);
    EXPECT_EQ(ret, 0);
    EXPECT_TRUE( (addr.sin_addr.s_addr == 0) ||
        (addr.sin_addr.s_addr == temp_addr.sin_addr.s_addr));
    EXPECT_EQ(addr.sin_family, temp_addr.sin_family);
    EXPECT_EQ(addr.sin_port, temp_addr.sin_port);

    long start_time = atol(env["START_TIME"].c_str());

    struct timeval tv;
    ret = gettimeofday(&tv, 0);
    EXPECT_EQ(ret, 0);

    long sleep_time = start_time - (1000*1000*tv.tv_sec) - tv.tv_usec;
    EXPECT_GE(sleep_time, 0);
    //printf("connect sleep: %ld\n", sleep_time);
    usleep(sleep_time);

    unsigned int seed = atoi(env["RANDOM_SEED"].c_str());
    int is_send = atoi(env["SENDER"].c_str());
    int buffer_size = atoi(env["BUFFER_SIZE"].c_str());
    int loop_count = atoi(env["LOOP_COUNT"].c_str());
    long expect_size = atoi(env["EXPECT_SIZE"].c_str());

    uint8_t* send_buffer = (uint8_t*)malloc(buffer_size);
    uint8_t* recv_buffer = (uint8_t*)malloc(buffer_size);

    int stop = 0;
    int loop = 0;
    long total_size = 0;
    int dem = 0;
    FILE * pFile;
    
    FILE* pFile1;
    
    //////fprintf(pFile, "is Send = %d \n", is_send);
    bool fail = false;
    processNumber++;
    std::string path("/home/vucuong12/Desktop/lab2/source_code/KENSv3/app/TestTCP/acceptso");
    std::string number = NumberToString(processNumber);
    path = path + number;
    pFile = fopen (path.c_str(),"w");
    ///////////////
    std::string path1("/home/vucuong12/Desktop/lab2/source_code/KENSv3/app/TestTCP/accept");
    std::string number1 = NumberToString(processNumber);
    path1 = path1 + number1;
    pFile1 = fopen (path1.c_str(),"w");
    ////fprintf(pFile, "processNumber = %d \n", processNumber);
    struct timeval dn;
    // ret = gettimeofday(&dn, 0);
    //            //fprintf(pFile, "Time start %ld\n", dn.tv_sec);
    int processNum = processNumber;
    int count = 0;
    while(!stop)
    {
      
      for(int k=0; k<buffer_size; k++)
        send_buffer[k] = rand_r(&seed) & 0xFF;

      if(is_send)
      {
        int remaining = buffer_size;
        int write_byte = 0;
        while((write_byte = write(client_fd, send_buffer + (buffer_size - remaining), remaining)) >= 0)
        {
          total_size += write_byte;
          remaining -= write_byte;
          EXPECT_GE(remaining, 0);
          if(remaining == 0)
            break;
        }
        if(write_byte < 0)
          break;
      }
      else
      {
        struct timeval dn;
        ret = gettimeofday(&dn, 0);
        ////fprintf(pFile, "Time while receiving %ld\n", dn.tv_sec);
        EXPECT_EQ(ret, 0);
        
        int remaining = buffer_size;
        int read_byte = 0;
        while((read_byte = read(client_fd, recv_buffer + (buffer_size - remaining), remaining)) >= 0)
        {
          // ret = gettimeofday(&dn, 0);
         //        //fprintf(pFile, "Time while receiving %ld\n", dn.tv_sec);
          total_size += read_byte;
          remaining -= read_byte;
          EXPECT_GE(remaining, 0);
          if(remaining == 0)
            break;
        }
        if(buffer_size - remaining > 0)
        {
          for(int j=0; j<buffer_size - remaining; j++)
          {
            ////fprintf(pFile, "given %08x read %08x\n", send_buffer[j], recv_buffer[j]);
            ////fprintf(pFile, "processNumber %d\n", processNumber);
            count++;
            if (1 < 300000){
              fprintf(pFile, "haha %04x\n", send_buffer[j]);  
              if (send_buffer[j] != recv_buffer[j]){
                //fprintf(pFile1, "---> %04x %04x\n", send_buffer[j], recv_buffer[j]);
                //fprintf(pFile, "pro: %d given %08x read %08x\n",processNum, send_buffer[j], recv_buffer[j]);
                fail = true;
              } else  {
                //fprintf(pFile1, "%04x %04x\n", send_buffer[j], recv_buffer[j]);
                // ret = gettimeofday(&dn, 0);
            //     //fprintf(pFile, "Time while receiving %ld\n", dn.tv_sec);
                //fprintf(pFile, "------------------------ given %08x read %08x\n", send_buffer[j], recv_buffer[j]);
              } 
            }
            
            EXPECT_EQ(send_buffer[j], recv_buffer[j]);
          }
        }
        if(read_byte < 0){
          ////fprintf(pFile, "Terminated at loop %d\n", loop + 1);
          break;
        }
      }

      loop++;
      if(loop_count != 0 && loop_count <= loop)
        break;
    }

    
    free(send_buffer);
    free(recv_buffer);

    EXPECT_EQ(expect_size, total_size);
    struct timeval timeval;
    gettimeofday(&timeval, 0);
    ////fprintf(pFile, "Time After receiving %ld\n", timeval.tv_sec);
    ////fprintf(pFile, "Is Sending %d\n", is_send);
    ////fprintf(pFile, "Is received %d\n", total_size);
    EXPECT_LT(timeval.tv_sec, connection_timeout);


    
    

    close(client_fd);
    close(server_socket);
    fprintf(pFile, "%d. DONE ACCEPT %d!\n", processNum, total_size);
    fclose (pFile);
    fclose (pFile1);
  }
};

int TestCongestion_Accept::processNumber = 0;

class TestCongestion_Connect : public SystemCallApplication, private TCPApplication
{
public:
	static int processNumber;
  TestCongestion_Connect(Host* host, const std::unordered_map<std::string, std::string> &env) : SystemCallApplication(host), TCPApplication(this)
{
    this->env = env;

}
protected:
  std::unordered_map<std::string, std::string> env;
protected:
  void E_Main()
  {
    FILE * pFile;
    
    long connect_time = atol(env["CONNECT_TIME"].c_str());
    usleep(connect_time);

    int client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in addr;
    socklen_t len = sizeof(addr);
    memset(&addr, 0, len);

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(env["CONNECT_ADDR"].c_str());
    addr.sin_port = htons(atoi(env["CONNECT_PORT"].c_str()));

    int ret = connect(client_socket, (struct sockaddr*)&addr, len);
    EXPECT_GE(ret, 0);

    struct sockaddr_in temp_addr;
    socklen_t temp_len = sizeof(temp_addr);
    ret = getpeername(client_socket, (struct sockaddr*)&temp_addr, &temp_len);
    EXPECT_EQ(ret, 0);
    EXPECT_EQ(addr.sin_addr.s_addr, temp_addr.sin_addr.s_addr);
    EXPECT_EQ(addr.sin_family, temp_addr.sin_family);
    EXPECT_EQ(addr.sin_port, temp_addr.sin_port);

    long start_time = atol(env["START_TIME"].c_str());

    struct timeval tv;
    ret = gettimeofday(&tv, 0);
    EXPECT_EQ(ret, 0);

    long sleep_time = start_time - (1000*1000*tv.tv_sec) - tv.tv_usec;
    EXPECT_GE(sleep_time, 0);
    //printf("connect sleep: %ld\n", sleep_time);
    usleep(sleep_time);

    unsigned int seed = atoi(env["RANDOM_SEED"].c_str());
    int is_send = atoi(env["SENDER"].c_str());
    int buffer_size = atoi(env["BUFFER_SIZE"].c_str());
    int loop_count = atoi(env["LOOP_COUNT"].c_str());
    long expect_size = atoi(env["EXPECT_SIZE"].c_str());

    uint8_t* send_buffer = (uint8_t*)malloc(buffer_size);
    uint8_t* recv_buffer = (uint8_t*)malloc(buffer_size);

    int stop = 0;
    int loop = 0;
    int dem = 0;
    long total_size = 0;
    processNumber++;
   	std::string path("/home/vucuong12/Desktop/lab2/source_code/KENSv3/app/TestTCP/connect");
    std::string number = NumberToString(processNumber);
    path = path + number;
    pFile = fopen (path.c_str(),"w");
    
    int processNum = processNumber;
    while(!stop)
    {
      for(int k=0; k<buffer_size; k++)
        send_buffer[k] = rand_r(&seed) & 0xFF;

      if(is_send)
      {
        int remaining = buffer_size;
        int write_byte = 0;
        while((write_byte = write(client_socket, send_buffer + (buffer_size - remaining), remaining)) >= 0)
        {
          for (int k = buffer_size - remaining; k < write_byte; k++){
            ////fprintf(pFile, "send %04x\n", send_buffer[k]);
          }
          total_size += write_byte;
          remaining -= write_byte;
          EXPECT_GE(remaining, 0);
          if(remaining == 0)
            break;
        }
        if(write_byte < 0){
          //fprintf(pFile, "DMDMDMDDM %d \n", loop);
          ////fprintf(pFile, "dem of return value -1 write is %d\n",++dem );
          //fprintf(pFile, "DMDMDMDDM %d \n", loop);
          
          break;
        }
      }
      else
      {
        int remaining = buffer_size;
        int read_byte = 0;
        while((read_byte = read(client_socket, recv_buffer + (buffer_size - remaining), remaining)) >= 0)
        {
          total_size += read_byte;
          remaining -= read_byte;
          EXPECT_GE(remaining, 0);
          if(remaining == 0)
            break;
        }
        if(buffer_size - remaining > 0)
        {
          for(int j=0; j<buffer_size - remaining; j++)
          {
            EXPECT_EQ(send_buffer[j], recv_buffer[j]);
          }
        }
        if(read_byte < 0)
          break;
      }

      loop++;
      ////fprintf(pFile, "LOOP is %d\n",loop );
      ////fprintf(pFile, "sent is %d\n",total_size );
      if(loop_count != 0 && loop_count <= loop)
        break;
    }

    free(send_buffer);
    free(recv_buffer);

    EXPECT_EQ(expect_size, total_size);
    ////fprintf(pFile, "is_send = %d\n", is_send );
    ////fprintf(pFile, "expect_size is %d\n", expect_size);
    ////fprintf(pFile, "buffer_size is %d\n", buffer_size);
    ////fprintf(pFile, "loop_count is %d\n", loop_count);
    ////fprintf(pFile, "Is sent %d\n", total_size);
    close(client_socket);
    fprintf(pFile, "%d. DONE SENDING total_size: %d\n" , processNum, total_size);
    fclose(pFile);
    
  }
};

int TestCongestion_Connect::processNumber = 0;

TEST_F(TestEnv_Congestion0, TestCongestion0)
{
  FILE * pFile;
  pFile = fopen ("/home/vucuong12/Desktop/lab2/source_code/KENSv3/app/TestTCP/test0.txt","w");
  std::unordered_map<std::string, std::string> accept_env;
  std::unordered_map<std::string, std::string> connect_env;

  uint8_t server_ip[4];
  server_host->getIPAddr(server_ip, 0);

  char str_buffer[128];
  snprintf(str_buffer, sizeof(str_buffer), "%u.%u.%u.%u", server_ip[0], server_ip[1], server_ip[2], server_ip[3]);
  std::string connect_addr(str_buffer);

  TestCongestion_Connect** clients = new TestCongestion_Connect*[num_client];
  TestCongestion_Accept** servers = new TestCongestion_Accept*[num_client];
  ////fprintf(pFile, "NUmber of clients is %d\n", num_cli                                                                                   ent);
  for(int k=0; k<num_client; k++)
  {
    snprintf(str_buffer, sizeof(str_buffer), "%d", k+10000);
    std::string connect_port(str_buffer);

    Time start_time = TimeUtil::makeTime(1,TimeUtil::SEC);
    start_time += TimeUtil::makeTime(0,TimeUtil::SEC);

    accept_env["RANDOM_SEED"] = "104729";
    accept_env["LISTEN_ADDR"] = "0.0.0.0";
    accept_env["LISTEN_PORT"] = connect_port;
    accept_env["BACKLOG"] = "1";
    accept_env["LISTEN_TIME"] = "0";
    accept_env["ACCEPT_TIME"] = TimeUtil::printTime(TimeUtil::makeTime(1000,TimeUtil::USEC), TimeUtil::USEC);
    accept_env["START_TIME"] = TimeUtil::printTime(start_time, TimeUtil::USEC);

    connect_env["RANDOM_SEED"] = "104729";
    connect_env["CONNECT_PORT"] = connect_port;
    connect_env["CONNECT_TIME"] = TimeUtil::printTime(TimeUtil::makeTime(2000,TimeUtil::USEC), TimeUtil::USEC);
    connect_env["START_TIME"] = TimeUtil::printTime(start_time, TimeUtil::USEC);

    connect_env["CONNECT_ADDR"] = connect_addr;
    connect_env["BUFFER_SIZE"] = "1024";
    connect_env["LOOP_COUNT"] = "100000";
    connect_env["SENDER"] = "1";
    connect_env["EXPECT_SIZE"] = "102400000";
    clients[k] = new TestCongestion_Connect(client_hosts[k], connect_env);

    accept_env["SENDER"] = "0";
    accept_env["BUFFER_SIZE"] = "1024";
    accept_env["LOOP_COUNT"] = "0";
    accept_env["EXPECT_SIZE"] = "102400000";
    accept_env["CONNECTION_TIMEOUT"] = "92";
    servers[k] = new TestCongestion_Accept(server_host, accept_env);

    clients[k]->initialize();
    servers[k]->initialize();
  }

  this->runTest();

  for(int k=0; k<num_client; k++)
  {
    delete servers[k];
    delete clients[k];
  }

  delete[] servers;
  delete[] clients;
  fclose(pFile);
}

TEST_F(TestEnv_Congestion1, TestCongestion1)
{
  FILE * pFile;
  pFile = fopen ("/home/vucuong12/Desktop/lab2/source_code/KENSv3/app/TestTCP/TestCongestion1.txt","w");
  std::unordered_map<std::string, std::string> accept_env;
  std::unordered_map<std::string, std::string> connect_env;

  uint8_t server_ip[4];
  server_host->getIPAddr(server_ip, 0);

  char str_buffer[128];
  snprintf(str_buffer, sizeof(str_buffer), "%u.%u.%u.%u", server_ip[0], server_ip[1], server_ip[2], server_ip[3]);
  std::string connect_addr(str_buffer);
  //num_client = 4;
  TestCongestion_Connect** clients = new TestCongestion_Connect*[num_client];
  TestCongestion_Accept** servers = new TestCongestion_Accept*[num_client];

  for(int k=0; k<num_client; k++)
  {
    snprintf(str_buffer, sizeof(str_buffer), "%d", k+10000);
    std::string connect_port(str_buffer);

    Time start_time = TimeUtil::makeTime(1,TimeUtil::SEC);
    start_time += TimeUtil::makeTime(0,TimeUtil::SEC);

    accept_env["RANDOM_SEED"] = "104729";
    accept_env["LISTEN_ADDR"] = "0.0.0.0";
    accept_env["LISTEN_PORT"] = connect_port;
    accept_env["BACKLOG"] = "1";
    accept_env["LISTEN_TIME"] = "0";
    accept_env["ACCEPT_TIME"] = TimeUtil::printTime(TimeUtil::makeTime(1000,TimeUtil::USEC), TimeUtil::USEC);
    accept_env["START_TIME"] = TimeUtil::printTime(start_time, TimeUtil::USEC);

    connect_env["RANDOM_SEED"] = "104729";
    connect_env["CONNECT_PORT"] = connect_port;
    connect_env["CONNECT_TIME"] = TimeUtil::printTime(TimeUtil::makeTime(2000,TimeUtil::USEC), TimeUtil::USEC);
    connect_env["START_TIME"] = TimeUtil::printTime(start_time, TimeUtil::USEC);

    connect_env["CONNECT_ADDR"] = connect_addr;
    connect_env["BUFFER_SIZE"] = "1024";
    connect_env["LOOP_COUNT"] = "10000";
    connect_env["SENDER"] = "1";
    connect_env["EXPECT_SIZE"] = "10240000";
    clients[k] = new TestCongestion_Connect(client_hosts[k], connect_env);

    accept_env["SENDER"] = "0";
    accept_env["BUFFER_SIZE"] = "1024";
    accept_env["LOOP_COUNT"] = "0";
    accept_env["EXPECT_SIZE"] = "10240000";
    accept_env["CONNECTION_TIMEOUT"] = "60";
    servers[k] = new TestCongestion_Accept(server_host, accept_env);

    clients[k]->initialize();
    servers[k]->initialize();
  }

  fprintf(pFile, "111DONEEEEE\n" );
  fclose(pFile);
  this->runTest();
  

  for(int k=0; k<num_client; k++)
  {
    delete servers[k];
    delete clients[k];
  }

  delete[] servers;
  delete[] clients;
  
}

TEST_F(TestEnv_Congestion2, TestCongestion2)
{
  FILE * pFile;
  pFile = fopen ("/home/vucuong12/Desktop/lab2/source_code/KENSv3/app/TestTCP/testOut2.txt","a");
  fprintf(pFile, "START !\n" );
  std::unordered_map<std::string, std::string> accept_env;
  std::unordered_map<std::string, std::string> connect_env;

  uint8_t server_ip[4];
  server_host->getIPAddr(server_ip, 0);

  char str_buffer[128];
  snprintf(str_buffer, sizeof(str_buffer), "%u.%u.%u.%u", server_ip[0], server_ip[1], server_ip[2], server_ip[3]);
  std::string connect_addr(str_buffer);

  TestCongestion_Connect** clients = new TestCongestion_Connect*[num_client];
  TestCongestion_Accept** servers = new TestCongestion_Accept*[num_client];

  for(int k=0; k<num_client; k++)
  {
    snprintf(str_buffer, sizeof(str_buffer), "%d", k+10000);
    std::string connect_port(str_buffer);

    Time start_time = TimeUtil::makeTime(1,TimeUtil::SEC);
    start_time += TimeUtil::makeTime(0,TimeUtil::SEC);

    accept_env["RANDOM_SEED"] = "104729";
    accept_env["LISTEN_ADDR"] = "0.0.0.0";
    accept_env["LISTEN_PORT"] = connect_port;
    accept_env["BACKLOG"] = "1";
    accept_env["LISTEN_TIME"] = "0";
    accept_env["ACCEPT_TIME"] = TimeUtil::printTime(TimeUtil::makeTime(1000,TimeUtil::USEC), TimeUtil::USEC);
    accept_env["START_TIME"] = TimeUtil::printTime(start_time, TimeUtil::USEC);

    connect_env["RANDOM_SEED"] = "104729";
    connect_env["CONNECT_PORT"] = connect_port;
    connect_env["CONNECT_TIME"] = TimeUtil::printTime(TimeUtil::makeTime(2000,TimeUtil::USEC), TimeUtil::USEC);
    connect_env["START_TIME"] = TimeUtil::printTime(start_time, TimeUtil::USEC);

    connect_env["CONNECT_ADDR"] = connect_addr;
    connect_env["BUFFER_SIZE"] = "1024";
    connect_env["LOOP_COUNT"] = "10000";
    connect_env["SENDER"] = "1";
    connect_env["EXPECT_SIZE"] = "10240000";
    clients[k] = new TestCongestion_Connect(client_hosts[k], connect_env);

    accept_env["SENDER"] = "0";
    accept_env["BUFFER_SIZE"] = "1024";
    accept_env["LOOP_COUNT"] = "0";
    accept_env["EXPECT_SIZE"] = "10240000";
    accept_env["CONNECTION_TIMEOUT"] = "150";
    servers[k] = new TestCongestion_Accept(server_host, accept_env);

    clients[k]->initialize();
    servers[k]->initialize();
  }
  fprintf(pFile, "FINISH0 !\n");
  fprintf(pFile, "FINISH1 !\n");
  fclose(pFile);
  this->runTest();

  for(int k=0; k<num_client; k++)
  {
    delete servers[k];
    delete clients[k];
  }

  delete[] servers;
  delete[] clients;

 
}
