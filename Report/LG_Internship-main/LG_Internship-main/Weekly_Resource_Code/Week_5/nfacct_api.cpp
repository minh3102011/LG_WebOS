#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_acct/libnetfilter_acct.h>
#include <linux/netfilter/nfnetlink_acct.h>
#include <linux/netfilter/nfnetlink.h>
#include <vector>
#include <string>

//Định nghĩa lớp AccountingObject
struct AccountingObject {
    time_t timestamp;
    std::string name;
    uint64_t pkts;
    uint64_t bytes;


    AccountingObject(time_t ts, const std::string& n, uint64_t p, uint64_t b)
        : timestamp(ts), name(n), pkts(p), bytes(b) {}
};
//Hàm xử lý kết quả từ kernel
static int nfacct_cb(const struct nlmsghdr *nlh, void *data) {
    std::vector<AccountingObject>& objects = *static_cast<std::vector<AccountingObject>*>(data);
    struct nfacct *acct = nfacct_alloc();  // Cấp phát bộ nhớ cho đối tượng nfacct
   
    if (acct == nullptr) {
        return MNL_CB_OK;  // Trả về nếu không cấp phát được bộ nhớ
    }
   
    // Phân tích payload của message từ kernel và lưu vào đối tượng nfacct
    if (nfacct_nlmsg_parse_payload(nlh, acct) == -1) {
        nfacct_free(acct);  // Giải phóng bộ nhớ nếu phân tích không thành công
        return MNL_CB_OK;
    }


    // Lấy số lượng gói tin và bytes từ đối tượng nfacct
    uint64_t pkts = nfacct_attr_get_u64(acct, NFACCT_ATTR_PKTS);
    uint64_t bytes = nfacct_attr_get_u64(acct, NFACCT_ATTR_BYTES);
   
    // In kết quả theo định dạng yêu cầu
    printf("{ pkts = %020lu, bytes = %020lu } = 0x%02x;\n", pkts, bytes, (int)(uintptr_t)acct);


    // Giải phóng bộ nhớ sau khi sử dụng
    nfacct_free(acct);
    return MNL_CB_OK;
}

//List API 
static int nfacct_cmd_list(int argc, char *argv[]) {
    struct mnl_socket *nl;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    unsigned int seq, portid;
    int ret, i;
    uint32_t mask = 0, value = 0;
   
    // Tạo socket Netlink
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        perror("mnl_socket_open");
        return -1;
    }


    // Liên kết socket với kernel
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        return -1;
    }


    portid = mnl_socket_get_portid(nl);


    // Tạo message header
    seq = time(NULL);
    nlh = nfacct_nlmsg_build_hdr(buf, NFNL_MSG_ACCT_GET, NLM_F_DUMP, seq);
    // Gửi message tới kernel
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        return -1;
    }


    // Nhận và xử lý các message trả về từ kernel
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    std::vector<AccountingObject> objects;


    while (ret > 0) {
        ret = mnl_cb_run(buf, ret, seq, portid, nfacct_cb, &objects);
        if (ret <= 0)
            break;
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }


    if (ret == -1) {
        perror("error");
        return -1;
    }


    mnl_socket_close(nl);


    return 0;
}

//Add API
static int nfacct_cmd_add(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s add <name> <pkts> <bytes>\n", argv[0]);
        return -1;
    }


    const char* name = argv[2];
    uint64_t pkts, bytes;


    // Chuyển đổi gói tin và bytes từ chuỗi sang số
    if (sscanf(argv[3], "%" PRIu64, &pkts) != 1 || sscanf(argv[4], "%" PRIu64, &bytes) != 1) {
        fprintf(stderr, "Invalid pkts or bytes value\n");
        return -1;
    }


    // Tạo đối tượng nfacct
    struct mnl_socket *nl;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct nfacct *acct;
    uint32_t portid, seq;
    int ret;


    acct = nfacct_alloc();
    if (acct == NULL) {
        perror("OOM");
        return -1;
    }


    nfacct_attr_set(acct, NFACCT_ATTR_NAME, name);
    nfacct_attr_set_u64(acct, NFACCT_ATTR_PKTS, pkts);
    nfacct_attr_set_u64(acct, NFACCT_ATTR_BYTES, bytes);


    // Tạo header của message Netlink
    seq = time(NULL);
    nlh = nfacct_nlmsg_build_hdr(buf, NFNL_MSG_ACCT_NEW, NLM_F_CREATE | NLM_F_ACK, seq);
    nfacct_nlmsg_build_payload(nlh, acct);


    // Giải phóng bộ nhớ nfacct
    nfacct_free(acct);


    // Mở socket Netlink
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        perror("mnl_socket_open");
        return -1;
    }


    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        return -1;
    }
    portid = mnl_socket_get_portid(nl);


    // Gửi message tới kernel
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        return -1;
    }


    // Nhận kết quả từ kernel
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (ret > 0) {
        ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
        if (ret <= 0)
            break;
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }


    if (ret == -1) {
        perror("error");
        return -1;
    }


    mnl_socket_close(nl);


    printf("Account added successfully: %s pkts = %" PRIu64 ", bytes = %" PRIu64 "\n", name, pkts, bytes);
    return 0;
}


//Delete API
static int nfacct_cmd_delete(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s delete <name>\n", argv[0]);
        return -1;
    }


    const char* name = argv[2];


    // Tạo đối tượng nfacct
    struct mnl_socket *nl;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr *nlh;
    struct nfacct *acct;
    uint32_t portid, seq;
    int ret;


    // Tạo bộ đếm để gửi xóa
    acct = nfacct_alloc();
    if (acct == NULL) {
        perror("OOM");
        return -1;
    }


    // Set tên của bộ đếm cần xóa
    nfacct_attr_set(acct, NFACCT_ATTR_NAME, name);


    // Tạo header của message Netlink
    seq = time(NULL);
    nlh = nfacct_nlmsg_build_hdr(buf, NFNL_MSG_ACCT_DEL, NLM_F_ACK, seq);
    nfacct_nlmsg_build_payload(nlh, acct);


    // Giải phóng bộ nhớ nfacct
    nfacct_free(acct);


    // Mở socket Netlink
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        perror("mnl_socket_open");
        return -1;
    }


    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        perror("mnl_socket_bind");
        return -1;
    }
    portid = mnl_socket_get_portid(nl);


    // Gửi message xóa tới kernel
    if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0) {
        perror("mnl_socket_send");
        return -1;
    }


    // Nhận kết quả từ kernel
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    while (ret > 0) {
        ret = mnl_cb_run(buf, ret, seq, portid, NULL, NULL);
        if (ret <= 0)
            break;
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
    }


    if (ret == -1) {
        perror("error");
        return -1;
    }


    mnl_socket_close(nl);


    printf("Account deleted successfully: %s\n", name);
    return 0;
}
