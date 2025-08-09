#include <iostream>
#include <vector>
#include <libnetfilter_acct/libnetfilter_acct.h>
#include <libmnl/libmnl.h>
#include <stdexcept>
#include <mutex>
#include <system_error>
#include <algorithm>
#include <ctime>
#include <cstddef>
#include <cstdlib>
#include <cstdio>
#include <stddef.h>
#include <stdint.h>
using namespace std;
 
class NfAcct {
public:
    NfAcct();
    void get(std::vector<nfacct*>& objects, bool reset);
    static int onListening(const struct nlmsghdr* nlh, void* data);
 
private:
    uint32_t genSeqUnlocked();
    void createSocket();
    void bindSocket();
    
    struct mnl_socket *nl;
    uint32_t portId;
    std::mutex nlMutex;
};
 
NfAcct::NfAcct() {
    createSocket();
    bindSocket();
    portId = mnl_socket_get_portid(nl);
}
 
void NfAcct::createSocket() {
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == nullptr)
        throw std::system_error(errno, std::generic_category());
}
 
void NfAcct::bindSocket() {
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        mnl_socket_close(nl);
        throw std::system_error(errno, std::generic_category());
    }
}
 
uint32_t NfAcct::genSeqUnlocked() {
    static uint32_t seq = 0;
    return ++seq;
}
 
void NfAcct::get(std::vector<nfacct*>& objects, bool reset) {
    char buf[MNL_SOCKET_BUFFER_SIZE * 2];
    struct nlmsghdr *nlh;
    std::lock_guard<std::mutex> lock(nlMutex);
 
    uint32_t seq = genSeqUnlocked();
    nlh = nfacct_nlmsg_build_hdr(buf, reset ? NFNL_MSG_ACCT_GET_CTRZERO : NFNL_MSG_ACCT_GET, NLM_F_DUMP, seq);
 
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) == -1)
        throw std::system_error(errno, std::generic_category());
 
    int ret;
    while ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0) {
        if ((ret = mnl_cb_run(buf, ret, seq, portId, onListening, &objects)) <= 0)
            break;
    }
 
    if (ret == -1)
        throw std::system_error(errno, std::generic_category());
}
 
int NfAcct::onListening(const struct nlmsghdr *nlh, void *data) {
    auto *objects = static_cast<std::vector<nfacct*>*>(data);
 
    struct nfacct *acct = nfacct_alloc();
    if (!acct) {
        std::cerr << "Error allocating memory for nfacct object\n";
        return MNL_CB_ERROR;
    }
 
    if (nfacct_nlmsg_parse_payload(nlh, acct) < 0) {
        nfacct_free(acct);
        std::cerr << "Error parsing Netlink payload\n";
        return MNL_CB_ERROR;
    }
 
    const char *name = nfacct_attr_get_str(acct, NFACCT_ATTR_NAME);
    if (!name) {
        nfacct_free(acct);
        return MNL_CB_OK;
    }
 
    objects->push_back(acct);
    return MNL_CB_OK;
}
 
 
void createAccountingObject(std::vector<nfacct*>& objects, bool reset) {
    struct nfacct *acct = nfacct_alloc();
    if (!acct) {
        std::cerr << "" << std::endl;
        return;
    }
 
    nfacct_attr_set_str(acct, NFACCT_ATTR_NAME, "example");  
    nfacct_attr_set_u64(acct, NFACCT_ATTR_BYTES, 0);          
    nfacct_attr_set_u64(acct, NFACCT_ATTR_PKTS, 0);          
 
    if (reset) {
        nfacct_attr_set_u64(acct, NFACCT_ATTR_BYTES, 0);
        nfacct_attr_set_u64(acct, NFACCT_ATTR_PKTS, 0);
    }
 
    objects.push_back(acct);
}
 
void addAccountingObject(std::vector<nfacct*>& objects, const std::string& name, uint64_t packets = 0, uint64_t bytes = 0, uint32_t flags = 0, uint64_t quota = 0) {
    struct nfacct *acct = nfacct_alloc();
    if (!acct) {
        std::cerr << "Failed to allocate memory for accounting object!" << std::endl;
        return;
    }
 
    nfacct_attr_set_str(acct, NFACCT_ATTR_NAME, name.c_str());
    nfacct_attr_set_u64(acct, NFACCT_ATTR_PKTS, packets);
    nfacct_attr_set_u64(acct, NFACCT_ATTR_BYTES, bytes);
    
    if (flags) {
        nfacct_attr_set(acct, NFACCT_ATTR_FLAGS, &flags);
        nfacct_attr_set_u64(acct, NFACCT_ATTR_QUOTA, quota);
    }
 
    objects.push_back(acct);
 
    try {
        struct mnl_socket *nl;
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh;
        uint32_t portid, seq;
 
        seq = time(NULL);
        nlh = nfacct_nlmsg_build_hdr(buf, NFNL_MSG_ACCT_NEW, NLM_F_CREATE | NLM_F_ACK, seq);
        nfacct_nlmsg_build_payload(nlh, acct);
 
        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (nl == NULL) {
            throw std::system_error(errno, std::generic_category());
        }
 
        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
            mnl_socket_close(nl);
            throw std::system_error(errno, std::generic_category());
        }
 
        portid = mnl_socket_get_portid(nl);
 
        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
            mnl_socket_close(nl);
            throw std::system_error(errno, std::generic_category());
        }
 
        int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        while (ret > 0) {
            ret = mnl_cb_run(buf, ret, seq, portid, nullptr, nullptr);
            if (ret <= 0) {
                break;
            }
            ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        }
 
        if (ret == -1) {
            mnl_socket_close(nl);
            throw std::system_error(errno, std::generic_category());
        }
 
        mnl_socket_close(nl);
 
    } catch (const std::exception& e) {
        std::cerr << "Error while adding accounting object to system: " << e.what() << std::endl;
    }
}
 
void removeAccountingObject(std::vector<nfacct*>& objects, const std::string& name) {
    bool objectFound = false;
 
    for (auto it = objects.begin(); it != objects.end();) {
        nfacct* acct = *it;
 
        if (nfacct_attr_get_str(acct, NFACCT_ATTR_NAME) == name) {
            objectFound = true;
            std::cout << "Attempting to remove accounting object: " << name << std::endl;
 
            try {
                struct mnl_socket* nl = nullptr;
                char buf[MNL_SOCKET_BUFFER_SIZE];
                struct nlmsghdr* nlh = nullptr;
                uint32_t portid = 0, seq = 0;
 
                seq = time(nullptr);
                nlh = nfacct_nlmsg_build_hdr(buf, NFNL_MSG_ACCT_DEL, NLM_F_ACK, seq);
                nfacct_nlmsg_build_payload(nlh, acct);
 
                nl = mnl_socket_open(NETLINK_NETFILTER);
                if (nl == nullptr) {
                    throw std::runtime_error("Failed to open Netlink socket");
                }
 
                if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
                    mnl_socket_close(nl);
                    throw std::runtime_error("Failed to bind Netlink socket");
                }
 
                portid = mnl_socket_get_portid(nl);
 
                if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
                    mnl_socket_close(nl);
                    throw std::runtime_error("Failed to send Netlink message");
                }
 
                int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
                while (ret > 0) {
                    ret = mnl_cb_run(buf, ret, seq, portid, nullptr, nullptr);
                    if (ret <= 0) {
                        break;
                    }
                    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
                }
 
                if (ret == -1) {
                    mnl_socket_close(nl);
                    throw std::runtime_error("Error receiving Netlink response");
                }
 
                mnl_socket_close(nl);
                std::cout << "Successfully removed accounting object: " << name << std::endl;
 
            } catch (const std::exception& e) {
                std::cerr << "Error removing accounting object: " << name << " - " << e.what() << std::endl;
            }
 
            nfacct_free(acct);
            it = objects.erase(it);
        } else {
            ++it;
        }
    }
 
    if (!objectFound) {
        std::cerr << "No accounting object found with name: " << name << std::endl;
    }
}
 
 
 
void printAccountingObjects(const std::vector<nfacct*>& objects) {
    for (const auto& obj : objects) {
        if (obj) {
            char buf[4096];
            nfacct_snprintf(buf, sizeof(buf), obj, NFACCT_ATTR_NAME, 0);
            std::cout << "Nfacct acc "
                      << nfacct_attr_get_str(obj, NFACCT_ATTR_NAME) << " "
                      << nfacct_attr_get_u64(obj, NFACCT_ATTR_PKTS) << " "
                      << nfacct_attr_get_u64(obj, NFACCT_ATTR_BYTES)
                      << std::endl;
        }
    }
}
 
void freeAccountingObjects(std::vector<nfacct*>& objects) {
    for (auto* acct : objects) {
        if (acct) {
            nfacct_free(acct);
        }
    }
    objects.clear();
}
 
int main() {
    std::vector<nfacct*> objects;
    NfAcct nfAcct;
    nfAcct.get(objects, true);
 
    int choice;
    std::string name;
    uint64_t pkts, bytes, quota;
    uint32_t flags;
 
    while (true) {
        // Hiển thị menu
        std::cout << "\nMenu:\n";
        std::cout << "1. Get accounting objects\n";
        std::cout << "2. Add accounting object\n";
        std::cout << "3. Remove accounting object\n";
        std::cout << "4. Print accounting objects\n";
        std::cout << "5. Exit\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;
 
        switch (choice) {
            case 1: {
                // Lấy danh sách tài khoản hiện có
                nfAcct.get(objects, true);
                std::cout << "Accounting objects have been updated.\n";
                break;
            }
 
            case 2: {
                // Thêm tài khoản mới
                std::cout << "Enter name of the new accounting object: ";
                std::cin >> name;
                std::cout << "Enter packets (default 0): ";
                std::cin >> pkts;
                std::cout << "Enter bytes (default 0): ";
                std::cin >> bytes;
                std::cout << "Enter flags (default 0): ";
                std::cin >> flags;
                std::cout << "Enter quota (default 0): ";
                std::cin >> quota;
 
                addAccountingObject(objects, name, pkts, bytes, flags, quota);
                std::cout << "Accounting object added successfully.\n";
                break;
            }
 
            case 3: {
                // Xóa tài khoản
                std::cout << "Enter name of the accounting object to remove: ";
                std::cin >> name;
 
                removeAccountingObject(objects, name);
                break;
            }
 
            case 4: {
                // In danh sách tài khoản hiện có
                printAccountingObjects(objects);
                break;
            }
 
            case 5: {
                // Thoát chương trình
                std::cout << "Exiting program...\n";
                freeAccountingObjects(objects);
                return 0;
            }
 
            default:
                std::cout << "Invalid choice. Please try again.\n";
        }
    }
 
    return 0;
}