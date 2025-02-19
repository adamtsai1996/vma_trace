#include "common.h"
#include "netlink.h"
#include "sha1.h"
/* global variables */
struct timespec start_time;
int task_stop;
static atomic_t key;
unsigned int worker_op;

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


#define MY_RB_SIZE 16384
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
	int len, idx, i;
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
			if (worker_op==BIO_COMPRESS) {
				lzo_dst_len=0;
				lzo_dst=vmalloc(lzo1x_worst_compress((meta->nr_pages)*PAGE_SIZE));
				lzo1x_1_compress(data,(meta->nr_pages)*PAGE_SIZE,lzo_dst,&lzo_dst_len,lzo_wrkmem);
				memset(msg, '\0', sizeof msg);
				sprintf(msg,"vma_trace,full_bio_lzo,%d,%s,%s,%c,%lu,%d,%d\n",
					meta->seq, meta->filename, meta->devname,
					meta->RW, meta->bi_sector, meta->nr_pages, lzo_dst_len);
				printk("%s", msg);
				vfree(lzo_dst);
			} else {
				for (i=0; i<meta->nr_pages; i++,data+=PAGE_SIZE) {
					switch(worker_op) {
					case SHA1:
						/* 4k sha1 */
						compute_sha( data, PAGE_SIZE, sha1);
						char_to_hex( sha1, sha1_hex, SHA1HashSize);
						/* 2k sha1 */
						compute_sha( data, PAGE_SIZE>>1, sha1);
						char_to_hex( sha1, sha1_hex_2k[0], SHA1HashSize);
						compute_sha( data+(PAGE_SIZE>>1), PAGE_SIZE>>1, sha1);
						char_to_hex( sha1, sha1_hex_2k[1], SHA1HashSize);
						/* 1k sha1 */
						compute_sha( data, PAGE_SIZE>>2, sha1);
						char_to_hex( sha1, sha1_hex_1k[0], SHA1HashSize);
						compute_sha( data+(PAGE_SIZE>>2), PAGE_SIZE>>2, sha1);
						char_to_hex( sha1, sha1_hex_1k[1], SHA1HashSize);
						compute_sha( data+(PAGE_SIZE>>2)*2, PAGE_SIZE>>2, sha1);
						char_to_hex( sha1, sha1_hex_1k[2], SHA1HashSize);
						compute_sha( data+(PAGE_SIZE>>2)*3, PAGE_SIZE>>2, sha1);
						char_to_hex( sha1, sha1_hex_1k[3], SHA1HashSize);
						memset(msg, '\0', sizeof msg);
						sprintf(msg,"vma_trace,sha,%d,%s,%s,%c,%lu,%d,%s,%s,%s,%s,%s,%s,%s\n",
							meta->seq, meta->filename, meta->devname,
							meta->RW, meta->bi_sector, i, sha1_hex,
							sha1_hex_2k[0],sha1_hex_2k[1],
							sha1_hex_1k[0],sha1_hex_1k[1],
							sha1_hex_1k[2],sha1_hex_1k[3]);
						printk("%s", msg);
						break;

					case PG_COMPRESS:
						lzo_dst_len=0;
						lzo_dst=vmalloc(lzo1x_worst_compress(PAGE_SIZE));
						lzo1x_1_compress(data,PAGE_SIZE,lzo_dst,&lzo_dst_len,lzo_wrkmem);
						memset(msg, '\0', sizeof msg);
						sprintf(msg,"vma_trace,lzo,%d,%s,%s,%c,%lu,%d,%d\n",
							meta->seq, meta->filename, meta->devname,
							meta->RW, meta->bi_sector, i, lzo_dst_len);
						printk("%s", msg);
						vfree(lzo_dst);
						break;

					case DIFF:
						diff_total = check_cache(data, meta->bi_sector+i*8, &diff_logs);
						if (diff_total>0) {
							memset(msg, '\0', sizeof msg);
							sprintf(msg,"vma_trace,dif,%d,%s,%s,%c,%lu,%d,%d,%d,%d,%d,%d\n",
							meta->seq, meta->filename, meta->devname,
							meta->RW, meta->bi_sector, i, diff_total,
							diff_interval[0],diff_interval[1],
							diff_interval[2],diff_interval[3]);
							printk("%s", msg);
						}
						diff_interval[0]=0;
						diff_interval[1]=0;
						diff_interval[2]=0;
						diff_interval[3]=0;
						break;
					}
				}
			}

			// release data
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
	char vm_file_name[256];
	int has_map=0;

	// get anon_vma
	anon_mapping = (unsigned long) ACCESS_ONCE(pg->mapping);
	if ((anon_mapping & PAGE_MAPPING_FLAGS)!=PAGE_MAPPING_ANON)
		return -1;
	av = (struct anon_vma *) (anon_mapping - PAGE_MAPPING_ANON);
	
	anon_vma_interval_tree_foreach(avc, &av->rb_root, pgoff, pgoff) {
		// get pte and ptl
		vma     = avc->vma;
		mm      = vma->vm_mm;
		address = vma_address(pg,vma);
		pmd     = mm_find_pmd(mm,address);
		pte     = pte_offset_map(pmd,address);
		ptl     = pte_lockptr(mm,pmd);

		// get swap_entry_t from pte
		spin_lock(ptl);
		arch_entry = __pte_to_swp_entry(*pte);
		spin_unlock(ptl);
		swap_entry = swp_entry(__swp_type(arch_entry),__swp_offset(arch_entry));

		// compare swap_entry_t in pte and page
		if (swap_entry.val == page_private(pg)) {

			pid  = mm->owner->pid;
			ppid = mm->owner->parent->pid;
			get_task_comm(task_comm,mm->owner);
			memset(vm_file_name, '\0', sizeof vm_file_name);
			if (vma->vm_file) {
				sprintf(vm_file_name,"%s",
						vma->vm_file->f_path.dentry->d_name.name);
			} else {
				sprintf(vm_file_name,"[anon]");
			}

			memset(msg, '\0', sizeof msg);
			sprintf(msg, "vma_trace,vma,%d,%d,%d,%s,%s,%lx,%lx\n",
					seq, pid, ppid, task_comm, vm_file_name,
					vma->vm_start, vma->vm_end);
			printk(msg);
			has_map=1;
		}
	}

	if (!has_map)
		return -2;

	return 0;
}


/* log function */
static int bio_log(int rw,struct bio *bio)
{
	trace_meta meta;
	int local_key;
	char msg[500];
	unsigned char *data;
	struct bio_vec *bvec;
	int i,ret;

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

	// we only care about swap out page
	if(meta.RW!='w') return 0;
	if( meta.devname[0]!='d' || meta.devname[1]!='m' ||
		meta.devname[2]!='-' || meta.devname[3]!='3')
	{
		return 0;
	}

	// dump vma info
	// there are at most 128 or 256 pages in one bio
	// so we use (key<<8 + page index in bio) to identify
	__bio_for_each_segment(bvec,bio,i,0) {
		ret=anon_page_dump(bvec->bv_page, (local_key<<8)+i);
		if (ret<0) {
			printk("vma_trace,ERR,7,%d\n",-ret);
			return 0;
		}
	}

	if (worker_op) {
		// allocate data for store swap out page
		// worker will do sha1 or compress on data later
		data = vmalloc(meta.nr_pages*PAGE_SIZE);
		if (!data) {
			printk("vma_trace,ERR,3,vmalloc data fail\n");
			return 0;
		}
		__bio_for_each_segment(bvec,bio,i,0) {
			get_page_data(bvec->bv_page, data+i*PAGE_SIZE);
		}
		if (push_rbuf_uninterruptable(data, &meta, &rbuf)) {
			vfree(data);
			return 0;
		}
		wake_up(&trace_wq);
	}

	return 0;
}
static int req_log(struct request *req)
{
	trace_meta meta;
	struct bio *bio=req->bio;
	char msg[300];

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

	if (worker_op>=NR_OPS) {
		printk("vma_trace,worker op fail!\n");
		goto fail;
	}

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

module_param(worker_op, uint, 0);
module_init(init_main);
module_exit(cleanup_main);
MODULE_LICENSE("GPL");

