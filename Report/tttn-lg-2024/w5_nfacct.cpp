#include <iostream>
#include <vector>
#include <libmnl/libmnl.h>
#include <libnetfilter_acct/libnetfilter_acct.h>
#include <system_error>
#include <mutex>
#include <ctime>
#include <inttypes.h>

class NfAcct
{
// private:
//     struct mnl_socket *nl;
//     uint32_t portId;
public:
    void myGet(bool reset)
    {
        struct mnl_socket *nl;
        uint32_t portId;
        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (nl == nullptr)
        {
            throw std::system_error(errno, std::generic_category());
        }

        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
        {
            mnl_socket_close(nl);
            throw std::system_error(errno, std::generic_category());
        }

        portId = mnl_socket_get_portid(nl);
        char buf[MNL_SOCKET_BUFFER_SIZE];
        struct nlmsghdr *nlh;
        unsigned int seq = time(NULL);
        int ret;

        nlh = nfacct_nlmsg_build_hdr(buf, reset ? NFNL_MSG_ACCT_GET_CTRZERO : NFNL_MSG_ACCT_GET, NLM_F_DUMP, seq);
        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) == -1)
        {
            throw std::system_error(errno, std::generic_category());
        }
        while ((ret = mnl_socket_recvfrom(nl, buf, sizeof(buf))) > 0)
        {
            if ((ret = mnl_cb_run(buf, ret, seq, portId, myGetCallback, NULL)) <= 0)
                break;
        }

        if (ret == -1)
        {
            throw std::system_error(errno, std::generic_category());
        }
        mnl_socket_close(nl);

    }

    void myAdd(const char *name)
    {
        struct mnl_socket *nl;
        uint32_t portId;
        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (nl == nullptr)
        {
            throw std::system_error(errno, std::generic_category());
        }

        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
        {
            mnl_socket_close(nl);
            throw std::system_error(errno, std::generic_category());
        }

        portId = mnl_socket_get_portid(nl);
        uint64_t pkts = 0;
        uint64_t bytes = 0;
        uint32_t seq = time(NULL);
        int ret;
        struct nfacct *nfacct = nfacct_alloc();
        struct nlmsghdr *nlh;
        char buf[MNL_SOCKET_BUFFER_SIZE];

        if (nfacct == nullptr)
        {
            throw std::system_error(errno, std::generic_category());
        }

        nfacct_attr_set(nfacct, NFACCT_ATTR_NAME, name);
        nfacct_attr_set_u64(nfacct, NFACCT_ATTR_PKTS, pkts);
        nfacct_attr_set_u64(nfacct, NFACCT_ATTR_BYTES, bytes);

        nlh = nfacct_nlmsg_build_hdr(buf, NFNL_MSG_ACCT_NEW, NLM_F_CREATE | NLM_F_ACK, seq);
        nfacct_nlmsg_build_payload(nlh, nfacct);
        nfacct_free(nfacct);

        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) == -1)
        {
            throw std::system_error(errno, std::generic_category());
        }
        while (ret > 0)
        {
            ret = mnl_cb_run(buf, ret, seq, portId, NULL, NULL);
            if (ret <= 0)
                break;
            ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        }
        if (ret == -1)
        {
            throw std::system_error(errno, std::generic_category());
        }
        mnl_socket_close(nl);
        
    }

    void myDelete(const char *name)
    {
        struct mnl_socket *nl;
        uint32_t portId;
        nl = mnl_socket_open(NETLINK_NETFILTER);
        if (nl == nullptr)
        {
            throw std::system_error(errno, std::generic_category());
        }

        if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
        {
            mnl_socket_close(nl);
            throw std::system_error(errno, std::generic_category());
        }

        portId = mnl_socket_get_portid(nl);
        uint32_t seq = time(NULL);
        int ret;
        struct nfacct *nfacct = nfacct_alloc();
        struct nlmsghdr *nlh;
        char buf[MNL_SOCKET_BUFFER_SIZE];

        if (nfacct == nullptr)
        {
            throw std::system_error(errno, std::generic_category());
        }

        nfacct_attr_set(nfacct, NFACCT_ATTR_NAME, name);

        nlh = nfacct_nlmsg_build_hdr(buf, NFNL_MSG_ACCT_DEL, NLM_F_ACK, seq);
        nfacct_nlmsg_build_payload(nlh, nfacct);
        nfacct_free(nfacct);

        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) == -1)
        {
            throw std::system_error(errno, std::generic_category());
        }

        while (ret > 0)
        {
            ret = mnl_cb_run(buf, ret, seq, portId, NULL, NULL);
            if (ret <= 0)
                break;
            ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        }
        if (ret == -1)
        {
            throw std::system_error(errno, std::generic_category());
        }
        mnl_socket_close(nl);

    }

private:
    static int myGetCallback(const struct nlmsghdr *nlh, void *data)
    {
        struct nfacct *nfacct = nfacct_alloc();

        if (nfacct == nullptr)
        {
            return MNL_CB_OK;
        }
        if (nfacct_nlmsg_parse_payload(nlh, nfacct) == -1)
        {
            nfacct_free(nfacct);
            return MNL_CB_OK;
        }

        uint64_t ptks = nfacct_attr_get_u64(nfacct, NFACCT_ATTR_PKTS);
        uint64_t bytes = nfacct_attr_get_u64(nfacct, NFACCT_ATTR_BYTES);
        const char *name = nfacct_attr_get_str(nfacct, NFACCT_ATTR_NAME);

        printf("Packets: %" PRIu64 "\n", ptks);
        printf("Bytes: %" PRIu64 "\n", bytes);
        printf("Name: %s\n", name);
        printf("-----------------------------\n\n");

        nfacct_free(nfacct);
        return MNL_CB_OK;
    }
};
int main() {
    try {
        NfAcct nfAcct;
        int choice = 0;
        std::string name;

        // Menu loop
        do {
            std::cout << "Choose an option:\n";
            std::cout << "1. Add a new account (myAdd)\n";
            std::cout << "2. Get account information (myGet)\n";
            std::cout << "3. Delete an account (myDelete)\n";
            std::cout << "4. Exit\n";
            std::cout << "Enter your choice: ";
            std::cin >> choice;
            std::cin.ignore();  // To discard the newline character left by std::cin

            switch (choice) {
                case 1:
                    // Option to add a new account
                    std::cout << "Enter the name for the new account: ";
                    std::getline(std::cin, name);
                    nfAcct.myAdd(name.c_str());
                    std::cout << "Account added successfully!\n";
                    break;
                case 2:
                    // Option to get account information
                    std::cout << "Getting account information...\n";
                    nfAcct.myGet(false);
                    break;
                case 3:
                    // Option to delete an account
                    std::cout << "Enter the name of the account to delete: ";
                    std::getline(std::cin, name);
                    nfAcct.myDelete(name.c_str());
                    std::cout << "Account deleted successfully!\n";
                    break;
                default:
                    // Exit option
                    std::cout << "Exiting...\n";
                    break;
            }

        } while (choice < 4);

    } catch (const std::exception &e) {
        // Catch any exceptions thrown during the process
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}