#include <iostream>
#include <fstream>
#include <string>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <libnetfilter_log/libnetfilter_log.h>
#include <netinet/ip.h>   
#include <netinet/tcp.h>  
#include <netinet/udp.h>  
#include <arpa/inet.h>
#include <chrono>
#include <ctime>


namespace fs = boost::filesystem;
namespace po = boost::program_options;

int main(int argc, char* argv[]) {
    std::string logFile;


    // Parse command line arguments
    po::options_description desc("Allowed options");
    desc.add_options()
        ("help,h", "Produce help message")
        ("logfile,l", po::value<std::string>(&logFile), "Path to the log file");


    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);


    if (vm.count("help") || !vm.count("logfile")) {
        std::cout << desc << std::endl;
        return 1;
    }


    // Initialize and start collecting logs
    LogCollector collector(logFile);
    collector.collectLogs();


    return 0;
}

LogCollector(const std::string& logFile) : logFile_(logFile), nflHandle(nullptr), nflGroupHandle(nullptr) {}
~LogCollector() {
    if (nflGroupHandle) nflog_unbind_group(nflGroupHandle);
    if (nflHandle) nflog_close(nflHandle);
}

void collectLogs() {
    std::ofstream logStream(logFile_, std::ios::app);
    if (!logStream.is_open()) {
        std::cerr << "Error opening log file: " << logFile_ << std::endl;
        return;
    }


    // Setup NFLOG and bind to group 1
    nflHandle = nflog_open();
    if (!nflHandle) {
        std::cerr << "Error opening nfnetlink handle" << std::endl;
        return;
    }


    if (nflog_bind_pf(nflHandle, AF_INET) < 0) {
        std::cerr << "Error binding to AF_INET" << std::endl;
        return;
    }


    nflGroupHandle = nflog_bind_group(nflHandle, 1);
    if (!nflGroupHandle) {
        std::cerr << "Error binding to NFLOG group 1" << std::endl;
        return;
    }


    nflog_set_mode(nflGroupHandle, NFULNL_COPY_PACKET, 0xffff);
    nflog_callback_register(nflGroupHandle, packetCallback, this);


    int fd = nflog_fd(nflHandle);
    char buffer[4096];


    while (true) {
        int len = recv(fd, buffer, sizeof(buffer), 0);
        if (len > 0) {
            nflog_handle_packet(nflHandle, buffer, len);
        }
    }


    logStream.close();
}
static int packetCallback(struct nflog_g_handle* groupHandle, struct nfgenmsg* nfmsg, struct nflog_data* nfa, void* data) {
    LogCollector* collector = static_cast<LogCollector*>(data);
    return collector->handlePacket(groupHandle, nfmsg, nfa);
}
int handlePacket(struct nflog_g_handle*, struct nfgenmsg*, struct nflog_data* nfa) {
    char* payload;
    int payloadLen = nflog_get_payload(nfa, &payload);


    if (payloadLen > 0) {
        struct iphdr* ipHeader = reinterpret_cast<struct iphdr*>(payload);


        // Extract source and destination IPs
        char srcIP[INET_ADDRSTRLEN], destIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ipHeader->saddr, srcIP, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ipHeader->daddr, destIP, INET_ADDRSTRLEN);


        std::ofstream logStream(logFile_, std::ios::app);
        logStream << "SRC: " << srcIP << " DST: " << destIP;


        if (ipHeader->protocol == IPPROTO_TCP) {
            struct tcphdr* tcpHeader = reinterpret_cast<struct tcphdr*>(payload + ipHeader->ihl * 4);
            logStream << " PROTO: TCP SPort: " << ntohs(tcpHeader->source) << " DPort: " << ntohs(tcpHeader->dest);
        } else if (ipHeader->protocol == IPPROTO_UDP) {
            struct udphdr* udpHeader = reinterpret_cast<struct udphdr*>(payload + ipHeader->ihl * 4);
            logStream << " PROTO: UDP SPort: " << ntohs(udpHeader->source) << " DPort: " << ntohs(udpHeader->dest);
        } else if (ipHeader->protocol == IPPROTO_ICMP) {
            logStream << " PROTO: ICMP";
        } else {
            logStream << " PROTO: OTHER";
        }


        logStream << std::endl;
        logStream.close();
    }


    return 0; // Indicate success
}
