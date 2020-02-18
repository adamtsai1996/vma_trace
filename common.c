#include "common.h"
void get_page_filename(struct page *page, char* output)
{
    int i, j, k; 
    struct dentry *p;

    unsigned char unknown[] = "unknown", null[]="NULL";
    unsigned char *pname;
    struct hlist_head *head;
    pname = null;
    i = j = k = 0;
    /* get filename */
    if(page && 
            page->mapping && 
            ((unsigned long) page->mapping & PAGE_MAPPING_ANON) == 0  && 
            page->mapping->host )
    {
        p = NULL ; 
        head = &(page->mapping->host->i_dentry);
        if( hlist_empty(head)) {
            goto END;
        }            
        p = hlist_entry_safe(head->first, struct dentry, d_alias);
        //p = list_first_entry(&(bio_page->mapping->host->i_dentry), struct dentry, d_alias);
        if(p != NULL ) {
            pname = p->d_iname;
            for(j = 0 ; j < strlen(p->d_iname); j++){
                if( (p->d_iname[j]!= '\0')  &&  ( (p->d_iname[j] < 32) || (p->d_iname[j] > 126))){ 
                    pname = unknown;
                    break;
                }
            }
			if(!strlen(pname))
				pname = null;
        }

    }
    if(pname != unknown &&  pname != null)
    {
        memcpy(output, pname, DNAME_INLINE_LEN);
		return;
    }
END:
    if(pname == unknown)
        memcpy(output, pname, 7 + 1);
    if(pname == null)
        memcpy(output, pname, 7 + 1);
    return;
}

void set_timestamp(struct timespec *cur_time, struct timespec *start_time)
{
    *cur_time = current_kernel_time();
    cur_time->tv_sec -= start_time->tv_sec;
    cur_time->tv_nsec -= start_time->tv_nsec;
    if(cur_time->tv_nsec < 0) {
        cur_time->tv_sec --;
        cur_time->tv_nsec += 1000000000L;
    }
    return;
}
int get_page_data(struct page *p, char *output)
{
    void *vpp = NULL;
    if(!p)
        return -1;
    vpp = kmap_atomic(p);
    if(!vpp)
        return -1;
    memcpy(output, (char *)vpp, PAGE_SIZE);
    kunmap_atomic(vpp);
    vpp = NULL;
    return 0;
}
void char_to_hex(char *in, char *out, int in_len)
{
    int i;
    for(i = 0; i < in_len ; i++) {
        sprintf(out+i*2, "%02x", in[i]); 
    }
    out[in_len*2] = '\0';
    return ;
}
void reposition(char *in, char* tmp)
{
    memcpy(tmp, in, 1024);
    memcpy(in, in+1024, 1024);
    memcpy(in+1024, in+2048, 1024);
    memcpy(in+2048, tmp,1024);
    return;
}

int diff_4KB(unsigned long sector, unsigned char *a, unsigned char *b, int*logs)
{
    unsigned char *p1, *p2;
    unsigned char tmp;
    int start, length;
    char buf[200];
    int interval[4];
    int ret;
    int i;
    int total = 0;
    int log_count;
    p1 = a;
    p2 = b;
    start = length = 0;
    total = 0;
    log_count = 0;
    memset(buf, '\0', sizeof buf);
    memset(interval, 0, sizeof interval);
    ret = sprintf(buf,"diff_d&");
    for(i = 0 ; i < (PAGE_SIZE); i++) {
        tmp = (*p1 ^ *p2);
        if(tmp != 0) { // diff
            if( length == 0 ) {
                start = i;
                length = 1;
            } else {
                length++;
            }
        } else {
            if(length > 0)
            {
                ret += sprintf(buf+ret,"%d#%d&", start, length);
                if(ret > 180) {
                    printk("%s\n", buf);
                    memset(buf, '\0', sizeof buf);
                    ret = sprintf(buf,"diff_dd&");
                }
                interval[start >>10]++;

                log_count ++;
                total += (length); // [start, offset, diffdata]
            }
            length = 0;
        }
        p1++;
        p2++;
    }
    if(length > 0) {
        log_count ++; 
        total += (length); // [start, offset, diffdata]

    }
    if(ret > 4)
        printk("%s\n", buf);
    printk("diff_s: %d&%d&%d&%d\n", interval[0],interval[1],interval[2],interval[3]);
    diff_interval[0] = interval[0];
    diff_interval[1] = interval[1];
    diff_interval[2] = interval[2];
    diff_interval[3] = interval[3];
    
    *logs = log_count;
    if(log_count > 0)
        return total;
    else
        return 0;
}
unsigned int  murmur_hash(uint32_t seed, unsigned int hash_size,  uint32_t key, uint32_t key_length) 
{
  uint32_t m = 0x5bd1e995;
  uint32_t r = 24;
  uint32_t h = seed ^ key_length;
  char * data = (char *)&key;

  while(key_length >= 4) {
    uint32_t k = key;
    k *= m;
    k ^= k >> r;
    k *= m;
    h *= m;
    h ^= k;
    data += 4;
    key_length -= 4;
  }
  
  switch(key_length) {
    case 3: h ^= data[2] << 16;
    case 2: h ^= data[1] << 8;
    case 1: h ^= data[0];
            h *= m;
  };

  h ^= h >> 13;
  h *= m;
  h ^= h >> 15;
  return h % hash_size;
}

