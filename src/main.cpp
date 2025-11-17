#include <iostream>
#include <exception>
#include <string>
#include <vector>
#include <fstream>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <stdio.h>
#include "include/json.hpp"

#pragma comment(lib, "ws2_32.lib") // Link Winsock library

const char* IPFILE = "data/ip_addr.json";

class Packet {
const char* IP_CONFIG_FILE = "data/tcpsyn_header.json";

typedef struct __attribute__((packed)){
        uint8_t version_ihl;
        uint8_t DSField_ECN;
        uint16_t total_length;
        uint16_t identification;
        uint16_t flags_fragoff;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t headerChecksum;
        uint32_t sourceIP;
        uint32_t destIP;
    } ipheader;
typedef struct __attribute__((packed)){
        uint16_t sourcePort;
        uint16_t destinationPort;
        uint32_t sequenceNumber;
        uint32_t acknumber;
        struct {
            unsigned headerLenght :4;
            unsigned reservedBits :6;
            unsigned URG :1;
            unsigned ACK :1;
            unsigned PSH :1;
            unsigned RST :1;
            unsigned SYN :1;
            unsigned FIN :1;
        }flags;
        uint16_t wSize;
        uint16_t checkSum;
        uint16_t urgentPointer;
    }tcpheader;

}

class IP{
struct IPP{
    std::string ipv4;
    std::vector<uint32_t> ports;
};


int readIpFile(){
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        std::cerr << "WSAStartup failed: " << iResult << "\n";
        return 1;
    }

    nlohmann::json json;
    std::ifstream file(IPFILE);
    if(!file.is_open()){
        std::cerr<<"file failed";
        throw -1;
    }
    file >> json;
    std::vector<std::thread> threads;
    for(const auto& item : json){
    threads.emplace_back([item](){
        auto* ipp = new IPP();
        ipp->ipv4 = item["ipv4"].get<std::string>();
        ipp->ports = item["ports"].get<std::vector<uint32_t>>();
        packetcrafting(ipp);
    });
    }
    for(auto &t : threads) t.join();
    
}
void packetcrafting(IPP* ipp){


}
}
int main(){
    try{

    }catch(int e){
        std::cerr<<"Welp" <<e;
    }
}