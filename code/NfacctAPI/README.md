# NfacctAPI
1.1. Concept 

nfacct is the command line tool to create/retrieve/delete accounting objects 

Main Features 

- listing the objects of the nfacct table in plain text/XML 

- automatically get and reset objects of the nfacct table 

- adding new objects to the nfacct table 

- deleting objects from the nfacct table 

1.2. libraries 

- libnetfilter_acct is the userspace library providing the interface to extended accounting infrastructure. 

- libmnl: is a minimalistic user-space library oriented to Netlink developers. There are a lot of common tasks in parsing, validating, and constructing of both the Netlink header and TLVs that are repetitive and easy to get wrong. This library aims to provide simple helpers that allow you to reuse code and avoid re-inventing the wheel 
Yêu cầu triển khai:

Dựa vào gợi ý về khái niệm và tính năng của Nfacct hãy xây dựng các file cấu hình của Nfacct để thêm/sửa/xoá các tài khoản.

Chú ý kết hợp với iptables để kiểm tra có thực hiện được các thao tác trên hay không?

Xây dựng API thực thi các công việc dựa vào Sequence Diagram trên
![image](https://github.com/user-attachments/assets/a1732f5a-34d6-472f-b68e-bdae6154feb3)

Link Report: https://hackmd.io/@iamproz2911/HJQqxwrPyg
