#include<linux/kernel.h>
#include<linux/init.h>
#include<linux/module.h>
#include<linux/moduleparam.h>


#include<asm/uaccess.h>
#include<linux/cdev.h>
#include<linux/proc_fs.h>
#include<linux/f2fs_fs.h>
#include<linux/vmalloc.h>
#define MAX_SIZE 100


#include<net/sock.h>
#include<linux/netlink.h>
#include<linux/skbuff.h>
#include<linux/bio.h>
#include<linux/kprobes.h>
#include<linux/kthread.h>
#include<linux/time.h>

#include<linux/mutex.h>
#include<linux/lzo.h>

#include<linux/mmc/mmc.h>
#include<linux/mmc/card.h>
#include<linux/mmc/host.h>
#include<linux/blkdev.h>
#include<linux/fs.h>

//for anon vma trace
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/rmap.h>
#include <linux/hugetlb.h>


#ifndef COMMON_H
#define COMMON_H
#define DEBUG 1


#define debug_print(fmt, ...) \
    do {if(DEBUG) printk("%s:%d" fmt, __FUNCTION__, __LINE__, __VA_ARGS__); \
    }while(0)

#define CACHE_SIZE (3072)
#define HASH_SEED (1512356891)
typedef struct {
    unsigned char buffer[PAGE_SIZE];
    unsigned long int sector;
}page_buf;
extern int diff_interval[4];

enum {
	NONE,
	SHA1,
	PG_COMPRESS,
	BIO_COMPRESS,
	DIFF,
	NR_OPS
};


void get_page_filename(struct page *page, char* output);
void set_timestamp(struct timespec *cur_time, struct timespec *start_time);
int get_page_data(struct page *p, char *output);
void char_to_hex(char *in, char *out, int in_len);
void reposition(char *in, char* tmp);
int diff_4KB(unsigned long sector, unsigned char *a, unsigned char *b, int*logs);
unsigned int  murmur_hash(uint32_t seed, unsigned int hash_size,  uint32_t key, uint32_t key_length); 
#endif
