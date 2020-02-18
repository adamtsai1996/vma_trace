#include "netlink.h"
#include "common.h"
void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid, res;
    pid = res = 0;
    nlh = (struct nlmsghdr*)skb->data;
    user_pid = nlh->nlmsg_pid;
    printk("Receive %s from %d\n", (char*) nlmsg_data(nlh), user_pid);
    if( strcmp((char *) nlmsg_data(nlh), "start") == 0) {
        trace_flag = 1;
    } else {
        trace_flag = 0;
    }
    return ;
}
void nl_send_msg(struct sock *nlsk, int dstPid, char* msg, int msgLen)
{
    struct sk_buff *skb;
    struct nlmsghdr *nlh;
    if(!nlsk || !msg)
        return;
    skb = alloc_skb(NLMSG_SPACE(msgLen), GFP_KERNEL);
    if(!skb) {
        debug_print("%s\n", "allocate skb fail");
        return;
    }
    nlh = nlmsg_put(skb, 0, 0, 0, msgLen, 0);
    NETLINK_CB(skb).portid = NETLINK_CB(skb).dst_group = 0;
    memcpy(NLMSG_DATA(nlh), msg, msgLen);
    netlink_unicast(nlsk, skb, dstPid, 1);
    return ;
}
int init_netlink(void) {
    struct netlink_kernel_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.input = nl_recv_msg;
    nl_sk = netlink_kernel_create(&init_net, NETLINK_MYTRACE, &cfg);
    if(!nl_sk) {
        printk("init netlink fail\n");
        return -1;
    }
    return 0;
}



