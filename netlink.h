#ifndef C_NETLINK_H
#define C_NETLINK_H

#include<net/sock.h>
#include<linux/netlink.h>
#include<linux/skbuff.h>

#define NETLINK_USER 31
#define NETLINK_MYTRACE 30

/* global variable used by netlink */
extern struct sock *nl_sk;
extern unsigned int user_pid;
extern int trace_flag; 


void nl_recv_msg(struct sk_buff *skb);
void nl_send_msg(struct sock *nlsk, int dstPid, char* msg, int msgLen);
int init_netlink(void);

#endif
