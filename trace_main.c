#include "common.h"
#include "netlink.h"
#include "sha1.h"
/* global variables */
struct timespec start_time;
int task_stop;
static atomic_t key;
static atomic_t vma_seq_key;

// for diff log
static page_buf *cache_memory;
int diff_interval[4];
int diff_total;
int diff_logs;

// for lzo compress
unsigned char lzo_wrkmem[LZO1X_1_MEM_COMPRESS];
unsigned char *lzo_dst;
size_t lzo_dst_len;

// for 4k/2k/1k-sha
unsigned char sha1[SHA1HashSize];
unsigned char sha1_hex[SHA1HashSize*2+1];
unsigned char sha1_hex_2k[2][SHA1HashSize*2+1];
unsigned char sha1_hex_1k[4][SHA1HashSize*2+1];

typedef struct _trace_meta {
	struct timespec time;
	unsigned long bi_sector;
	unsigned int nr_pages;
	int data_idx;
	int seq;
	int cpu_num;
	pid_t pid;
	char RW;
	char taskcomm[TASK_COMM_LEN];
	char filename[DNAME_INLINE_LEN];
	char devname[BDEVNAME_SIZE];
} trace_meta;

typedef struct _trace_data {
	trace_meta meta;
	unsigned char *data_ptr;
} trace_data;


#define MY_RB_SIZE 4096
DEFINE_SPINLOCK(rbuf_lock);
typedef struct _ring_buf {
	trace_data items[MY_RB_SIZE];
	int in;
	int out;
} trace_ring_buf;
/* worker thread variables*/
static struct task_struct *trace_worker;
DECLARE_WAIT_QUEUE_HEAD(trace_wq);

/* global ring buf */
trace_ring_buf rbuf = {
    .in = 0,
    .out = 0,
};

static inline unsigned long
__vma_address(struct page *page, struct vm_area_struct *vma)
{
	pgoff_t pgoff = page->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);

	if (unlikely(is_vm_hugetlb_page(vma)))
		pgoff = page->index << huge_page_order(page_hstate(page));

	return vma->vm_start + ((pgoff - vma->vm_pgoff) << PAGE_SHIFT);
}

inline unsigned long
vma_address(struct page *page, struct vm_area_struct *vma)
{
	unsigned long address = __vma_address(page, vma);

	/* page should be within @vma mapping range */
	VM_BUG_ON(address < vma->vm_start || address >= vma->vm_end);

	return address;
}

pmd_t *mm_find_pmd(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd = NULL;
	
	pgd = pgd_offset(mm,address);
	if(!pgd_present(*pgd)){
		goto out;
	}
	pud = pud_offset(pgd,address);
	if(!pud_present(*pud)){
		goto out;
	}
	pmd = pmd_offset(pud,address);
	if(!pmd_present(*pmd)){
		pmd = NULL;
	}
out:
	return pmd;

}

static int check_cache(unsigned char *data, unsigned long int sector, int *logs )
{
	unsigned int hash_index;
	int total;
	page_buf *page_bf;
	
	hash_index = murmur_hash(HASH_SEED, CACHE_SIZE, sector, sizeof(sector));
	page_bf = &cache_memory[hash_index];

	total=-1;
	if (page_bf->sector==sector) {
		total = diff_4KB(sector, data, page_bf->buffer, logs);
	}
	memcpy(page_bf->buffer, data, PAGE_SIZE);
	page_bf->sector = sector;

	return total;
}

int push_rbuf_uninterruptable(unsigned char *data ,trace_meta *meta, trace_ring_buf *_rbuf)
{
	int index;
	spin_lock(&rbuf_lock);
	if (MY_RB_SIZE <= _rbuf->in - _rbuf->out) {
		spin_unlock(&rbuf_lock);
		printk("vma_trace,ERR,5,rbuf full,%d,%d\n",meta->seq,meta->nr_pages);
		return -1;
	}
	index = _rbuf->in & (MY_RB_SIZE-1);
	if (meta) {
		_rbuf->items[index].meta.time.tv_sec	= meta->time.tv_sec;
		_rbuf->items[index].meta.time.tv_nsec	= meta->time.tv_nsec;
		_rbuf->items[index].meta.bi_sector		= meta->bi_sector;
		_rbuf->items[index].meta.nr_pages		= meta->nr_pages;
		_rbuf->items[index].meta.seq			= meta->seq;
		_rbuf->items[index].meta.cpu_num		= meta->cpu_num;
		_rbuf->items[index].meta.pid			= meta->pid;
		_rbuf->items[index].meta.RW				= meta->RW;
		memcpy(_rbuf->items[index].meta.taskcomm, meta->taskcomm, TASK_COMM_LEN);
		memcpy(_rbuf->items[index].meta.filename, meta->filename, DNAME_INLINE_LEN);
		memcpy(_rbuf->items[index].meta.devname, meta->devname, BDEVNAME_SIZE);
	}
	if (data) {
		_rbuf->items[index].data_ptr = data;
	} else {
		_rbuf->items[index].data_ptr = NULL;
	}
	_rbuf->in += 1;
	spin_unlock(&rbuf_lock);
	return 0;
}

bool rbuf_not_empty(trace_ring_buf *_rbuf)
{
	return _rbuf->in - _rbuf->out > 0;
}

int trace_rb_pop_all(trace_ring_buf *_rbuf)
{
	trace_meta *meta;
	int len, idx;
//	int i;
	char msg[500];
	unsigned char *data;

	spin_lock(&rbuf_lock);
	len = _rbuf->in - _rbuf->out;
	spin_unlock(&rbuf_lock);
	if (len<=0) return -1;

	while (len) {
		idx = _rbuf->out & (MY_RB_SIZE-1);
		meta = &_rbuf->items[idx].meta;
		data = _rbuf->items[idx].data_ptr;
		if (data) {
			/* 4k page granule */
//			for (i=0; i<meta->nr_pages; i++,data+=PAGE_SIZE) {
				
				/* for diff log */
//				diff_total = check_cache(data, meta->bi_sector+i*8, &diff_logs);
//				if (diff_total>0) {
//					memset(msg, '\0', sizeof msg);
//					sprintf(msg,"vma_trace,dif,%d,%s,%s,%c,%lu,%d,%d,%d,%d,%d,%d\n",
//						meta->seq, meta->filename, meta->devname,
//						meta->RW, meta->bi_sector, i, diff_total,
//						diff_interval[0],diff_interval[1],
//						diff_interval[2],diff_interval[3]);
//					printk("%s", msg);
//				}
//				diff_interval[0]=0;
//				diff_interval[1]=0;
//				diff_interval[2]=0;
//				diff_interval[3]=0;

				/* for lzo compress */
//				lzo_dst_len=0;
//				lzo1x_1_compress(data,PAGE_SIZE,lzo_dst,&lzo_dst_len,lzo_wrkmem);
//				memset(msg, '\0', sizeof msg);
//				sprintf(msg,"vma_trace,lzo,%d,%s,%s,%c,%lu,%d,%d\n",
//					meta->seq, meta->filename, meta->devname,
//					meta->RW, meta->bi_sector, i, lzo_dst_len);
//				printk("%s", msg);

				/* for 4k/2k/1k-sha */
				/* calculate 4k sha1 */
//				compute_sha( data, PAGE_SIZE, sha1);
//				char_to_hex( sha1, sha1_hex, SHA1HashSize);
				/* calculate 2k sha1 */
//				compute_sha( data, PAGE_SIZE>>1, sha1);
//				char_to_hex( sha1, sha1_hex_2k[0], SHA1HashSize);
//				compute_sha( data+(PAGE_SIZE>>1), PAGE_SIZE>>1, sha1);
//				char_to_hex( sha1, sha1_hex_2k[1], SHA1HashSize);
				/* calculate 1k sha1 */
//				compute_sha( data, PAGE_SIZE>>2, sha1);
//				char_to_hex( sha1, sha1_hex_1k[0], SHA1HashSize);
//				compute_sha( data+(PAGE_SIZE>>2), PAGE_SIZE>>2, sha1);
//				char_to_hex( sha1, sha1_hex_1k[1], SHA1HashSize);
//				compute_sha( data+(PAGE_SIZE>>2)*2, PAGE_SIZE>>2, sha1);
//				char_to_hex( sha1, sha1_hex_1k[2], SHA1HashSize);
//				compute_sha( data+(PAGE_SIZE>>2)*3, PAGE_SIZE>>2, sha1);
//				char_to_hex( sha1, sha1_hex_1k[3], SHA1HashSize);
//				memset(msg, '\0', sizeof msg);
//				sprintf(msg,"vma_trace,sha,%d,%s,%s,%c,%lu,%d,%s,%s,%s,%s,%s,%s,%s\n",
//					meta->seq, meta->filename, meta->devname,
//					meta->RW, meta->bi_sector, i, sha1_hex,
//					sha1_hex_2k[0],sha1_hex_2k[1],
//					sha1_hex_1k[0],sha1_hex_1k[1],
//					sha1_hex_1k[2],sha1_hex_1k[3]);
//				printk("%s", msg);
//			}

			/* full bio pages granule compress*/
			lzo_dst_len=0;
			lzo_dst=vmalloc(lzo1x_worst_compress(meta->nr_pages*PAGE_SIZE));
			lzo1x_1_compress(data,PAGE_SIZE*meta->nr_pages,lzo_dst,&lzo_dst_len,lzo_wrkmem);
			memset(msg, '\0', sizeof msg);
			sprintf(msg,"vma_trace,full_bio_lzo,%d,%s,%s,%c,%lu,%d,%d\n",
				meta->seq, meta->filename, meta->devname,
				meta->RW, meta->bi_sector, meta->nr_pages, lzo_dst_len);
			printk("%s", msg);
			vfree(lzo_dst);
			vfree(_rbuf->items[idx].data_ptr);
			_rbuf->items[idx].data_ptr=NULL;
		}
		_rbuf->out += 1;
		len--;
	}
	return 0;
}

static int anon_page_dump(struct page *pg, int seq){
	// anon page reverse mapping
	struct anon_vma *av;
	struct anon_vma_chain *avc;
	unsigned long anon_mapping;
	pgoff_t pgoff = pg->index << (PAGE_CACHE_SHIFT-PAGE_SHIFT);
	struct vm_area_struct *vma;
	
	// search mapping pte
	struct mm_struct *mm;
	unsigned long address;
	pmd_t *pmd;
	pte_t *pte;
	spinlock_t *ptl;
	swp_entry_t arch_entry, swap_entry;

	// dump info
	pid_t pid, ppid;
	char task_comm[TASK_COMM_LEN], msg[700];
	char f_name[256];

	anon_mapping = (unsigned long) ACCESS_ONCE(pg->mapping);
	if((anon_mapping & PAGE_MAPPING_FLAGS)!=PAGE_MAPPING_ANON){
		printk("vma_trace,ERR,7,not anon mapping\n");
		return -1;
	}
	av = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	
	anon_vma_interval_tree_foreach(avc, &av->rb_root, pgoff, pgoff) {
		vma = avc->vma;
		mm = vma->vm_mm;
		address = vma_address(pg,vma);
		pmd = mm_find_pmd(mm,address);
		pte=pte_offset_map(pmd,address);
		ptl = pte_lockptr(mm,pmd);

		spin_lock(ptl);
		arch_entry = __pte_to_swp_entry(*pte);
		spin_unlock(ptl);
		
		swap_entry = swp_entry(__swp_type(arch_entry),__swp_offset(arch_entry));
		if(swap_entry.val == page_private(pg)){
			get_task_comm(task_comm,mm->owner);
			pid = mm->owner->pid;
			ppid = mm->owner->parent->pid;
			memset(f_name, '\0', sizeof f_name);
			if(vma->vm_file){
				sprintf(f_name,"%s",vma->vm_file->f_path.dentry->d_name.name);
			} else{
				sprintf(f_name,"[anon]");
			}
			memset(msg, '\0', sizeof msg);
			sprintf(msg,"vma_trace,vma,%d,%d,%d,%s,%s,%lx,%lx\n",
					seq,pid,ppid,task_comm,f_name,
					vma->vm_start,vma->vm_end);
			printk(msg);
		}
	}
	return 0;
}


/* log function */
static int bio_log(int rw,struct bio *bio)
{
	trace_meta meta;
	int local_key;
	char msg[500];
	//unsigned char *data;
	//struct bio_vec *bvec;
	//int i

	// set trace_meta
	local_key = atomic_read(&key);
	local_key = atomic_cmpxchg(&key, local_key, local_key+1);
	meta.seq = local_key;
	bio->trace_seq = meta.seq;
	set_timestamp(&meta.time, &start_time);
	meta.cpu_num = smp_processor_id();
	meta.RW = (rw&WRITE) ? 'w' : 'r';
	meta.bi_sector = bio->bi_sector;
	meta.nr_pages = bio->bi_vcnt;
	meta.pid = current->pid;
	memset(meta.taskcomm, '\0', TASK_COMM_LEN);
	sprintf(meta.taskcomm, "%s", current->comm);
	memset(meta.filename, '\0', DNAME_INLINE_LEN);
	get_page_filename(bio_iovec_idx(bio,0)->bv_page, meta.filename);
	memset(meta.devname, '\0', BDEVNAME_SIZE);
	if (bio->bi_bdev) {
		bdevname(bio->bi_bdev, meta.devname);
	} else {
		sprintf(meta.devname, "NDEV");
	}

	// bio trace log
	memset(msg, '\0', sizeof msg);
	sprintf(msg, "vma_trace,bio,%d,%s,%c,%lu,%d,%s\n",
		meta.seq, meta.devname, meta.RW,meta.bi_sector,
		meta.nr_pages,meta.filename);
	printk(msg);

	/*
	if(meta.RW!='w') return 0;
	if( meta.devname[0]!='d' || meta.devname[1]!='m' ||
		meta.devname[2]!='-' || meta.devname[3]!='3')
	{
		return 0;
	}

	// allocate and copy page data
	data = vmalloc(meta.nr_pages*PAGE_SIZE);
	if (!data) {
		printk("vma_trace,ERR,3,vmalloc data fail\n");
		return -1;
	}
	__bio_for_each_segment(bvec,bio,i,0) {
		if (i>=meta.nr_pages) {
			printk("vma_trace,ERR,4,iterate page fault\n");
			break;
		}
		get_page_data(bvec->bv_page, data+i*PAGE_SIZE);
	}

	if (push_rbuf_uninterruptable(data,&meta, &rbuf)) {
		vfree(data);
		return -1;
	}
	wake_up(&trace_wq);
	*/
	return 0;
}
static int req_log(struct request *req)
{
	trace_meta meta;
	struct bio *bio=req->bio;
	struct bio_vec *bvec;
	unsigned char *data;
	char msg[300];
	int i, local_key;

	// set trace_meta
	meta.seq = bio->trace_seq;
	set_timestamp(&meta.time, &start_time);
	meta.cpu_num = smp_processor_id();
	meta.RW = rq_data_dir(req)==WRITE ? 'w' : 'r';
	meta.bi_sector = blk_rq_pos(req);
	meta.nr_pages = blk_rq_bytes(req)>>12;
	meta.pid = current->pid;
	memset(meta.taskcomm, '\0', TASK_COMM_LEN);
	sprintf(meta.taskcomm, "%s", current->comm);
	memset(meta.filename, '\0', DNAME_INLINE_LEN);
	get_page_filename(bio_iovec_idx(bio,0)->bv_page, meta.filename);
	memset(meta.devname, '\0', BDEVNAME_SIZE);
	if (bio->bi_bdev) {
		bdevname(bio->bi_bdev, meta.devname);
	} else {
		sprintf(meta.devname, "NDEV");
	}

	// req trace log
	memset(msg,'\0', sizeof msg);
	sprintf(msg, "vma_trace,mmc,%d,%s,%c,%lu,%d,%s,%lld.%.9ld\n",
		meta.seq,meta.devname,meta.RW,meta.bi_sector,
		meta.nr_pages,meta.filename,
		(long long)meta.time.tv_sec,
		meta.time.tv_nsec);
	printk(msg);
	
	if (meta.RW!='w') return 0;
	if (meta.bi_sector < 110247936)
	{
		return 0;
	}


	// vma reverse map
	__bio_for_each_segment(bvec,bio,i,0) {
		local_key = atomic_read(&vma_seq_key);
		local_key = atomic_cmpxchg(&vma_seq_key, local_key, local_key+1);
		anon_page_dump(bvec->bv_page, local_key);
	}
/*
	// allocate and copy page data
	data = vmalloc(meta.nr_pages*PAGE_SIZE);
	if (!data) {
		printk("vma_trace,ERR,3,vmalloc data fail\n");
		return -1;
	}
	__bio_for_each_segment(bvec,bio,i,0) {
		if (i>=meta.nr_pages) {
			printk("vma_trace,ERR,4,iterate page fault\n");
			break;
		}
		get_page_data(bvec->bv_page, data+i*PAGE_SIZE);
	}

	if (push_rbuf_uninterruptable(data,&meta, &rbuf)) {
		vfree(data);
		return -1;
	}
	wake_up(&trace_wq);
*/
	return 0;
}


/* worker thread */
static int worker_func(void *data) {
	printk("vma_trace,INFO,worker thread start\n");
	while (!task_stop) {
		trace_rb_pop_all(&rbuf);
		wait_event(trace_wq, rbuf_not_empty(&rbuf));
	}
	printk("vma_trace,INFO,worker thread exit\n");
	return 0;
}

/* netlink interface */
struct sock *nl_sk = NULL;
unsigned int user_pid; 
int trace_flag;

/* jprobe function */
static void submit_bio_prehandler(int rw, struct bio *bio)
{
	if (bio_has_data(bio)) bio_log(rw,bio);
	jprobe_return();
}
static void mmc_req_prehandler(struct request *req)
{
	if (req) req_log(req);
	jprobe_return();
}
static struct jprobe submit_bio_probe = {
	.entry = submit_bio_prehandler,
	.kp = {
		.symbol_name = "submit_bio",
		.addr = NULL,
	},
};
static struct jprobe mmc_req_probe = {
	.entry = mmc_req_prehandler,
	.kp = {
		.symbol_name = "my_mmc_trace_fn",
		.addr = NULL,
	}
};
static int init_jprobe(void)
{
	int ret = 0;
	ret = register_jprobe(&submit_bio_probe);
	if(ret <0){
		printk("vma_trace,ERR,2,%s:%d jprobe fail\n", __FUNCTION__, __LINE__);
		return ret;
	}
	ret = register_jprobe(&mmc_req_probe);
	if(ret <0){
		printk("vma_trace,ERR,2,%s:%d jprobe fail\n", __FUNCTION__, __LINE__);
		return ret;
	}
	printk("vma_trace,INFO,init jprobe success\n");
	return 0;
}
static int init_trace_worker(void)
{
	task_stop = 0;
	trace_worker = kthread_run(worker_func, NULL, "vma_trace_thread");
	if (IS_ERR(trace_worker)) {
		task_stop = 1;
		printk("vma_trace,ERR,1,create worker\n");
		return -1;
	} else {
		printk("vma_trace,INFO,create worker success\n");
	}
	return 0;
}
static void cleanup_main(void)
{
	unregister_jprobe(&submit_bio_probe);
	unregister_jprobe(&mmc_req_probe);
	netlink_kernel_release(nl_sk);
	task_stop = 1;
	wake_up(&trace_wq);
	vfree(cache_memory);
	printk("vma_trace,INFO,exit kernel\n");
}
static int init_main(void)
{
	int ret;
	int num_cpu = num_online_cpus();
	atomic_set(&key, 0);
	diff_interval[0]=0;
	diff_interval[1]=0;
	diff_interval[2]=0;
	diff_interval[3]=0;
	trace_flag = 0;
	start_time = current_kernel_time();
	ret = init_netlink();
	if (ret<0||num_cpu<0) {
		goto fail;
	}
	ret = init_trace_worker();
	if (ret<0||num_cpu<0) {
		goto fail;
	}
	ret = init_jprobe();
	if (ret<0||num_cpu<0) {
		goto fail;
	}
	cache_memory = vmalloc(CACHE_SIZE*sizeof(page_buf));
	memset(cache_memory, 0, CACHE_SIZE*sizeof(page_buf));
	if(!cache_memory) {
		printk("vma_trace,ERR,6,alloc cache_memory fail\n");
		goto fail;
	}
	printk("vma_trace,init done!\n");
	return 0;
fail:
	cleanup_main();
	return -EBUSY;
}


module_init(init_main);
module_exit(cleanup_main);
MODULE_LICENSE("GPL");

