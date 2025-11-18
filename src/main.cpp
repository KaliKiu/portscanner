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
#include <memory>

class IP{
public:
    
    struct IPP{
        std::string ipv4;
        std::vector<uint32_t> ports;
    };
      struct ipheader {
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
    } __attribute__((packed));

     struct tcpheader{
        uint16_t sourcePort;
        uint16_t destinationPort;
        uint32_t sequenceNumber;
        uint32_t acknumber;
        struct {
            unsigned headerLength :4;
            unsigned reservedBits :6;
            unsigned URG :1;
            unsigned ACK :1;
            unsigned PSH :1;
            unsigned RST :1;
            unsigned SYN :1;
            unsigned FIN :1;
        } __attribute__((packed));
        uint16_t wSize;
        uint16_t checkSum;
        uint16_t urgentPointer;
    }tcpheader;
    inline static constexpr const char* IP_CONFIG_FILE = "data/tcpsyn_header.json";
    inline static constexpr const char* IPFILE = "data/ip_addr.json";
    
};


std::unique_ptr<IP::ipheader> ipHeader(IP::IPP* ipp){
    nlohmann::json json;
    std::ifstream file(IP::IP_CONFIG_FILE);
    if(!file.is_open()){
        std::cerr<<"IP_CONFIG_FILE ERR";
        throw -1;
    }
    file >>json; 
    std::unique_ptr<IP::ipheader> p = std::make_unique<IP::ipheader>();
    uint8_t version = json["version"];
    uint8_t ihl = json["ihl"];
    version &= 0x0F;
    ihl &= 0xF;

    //8bit
    p->version_ihl = ((version<<4) | ihl);
    p->DSField_ECN = json["DSField_ECN"];
    //16bit
    p->total_length = htons(json["total_length"]);
    p->identification = htons(json["id"]);
    p->flags_fragoff = htons(json["flags_fragoff"]);
    //8bit
    p->ttl = json["ttl"];
    p->protocol = json["protocol"];
    //32bit (already network byte order)
    p->sourceIP = Packet::parseIPAddress(json["sourceIP"]);
    p->destIP= Packet::parseIPAddress(json["destIP"][ip]);
    std::cout <<"MEOW" <<p->destIP;
    return p;
}

int readIpFile(){

    nlohmann::json json;
    std::ifstream file(IPFILE);
    if(!file.is_open()){
        std::cerr<<"IP_FILE ERR";
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

    std::unique_ptr<IP::ipheader> h= ipHeader(ipp);
    //iphdr (reusable)
    // loop for each port tcp headercrafting -> send ->new ->return

}


int main(){
    try{

    }catch(int e){
        std::cerr<<"Welp" <<e;
    }
}