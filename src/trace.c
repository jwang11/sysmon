#include "sysmon.h"

// Trace interface
struct trace_entry {
	uint64_t		time;
	uint32_t		cpu;
	uint32_t		res;
	__u32			size;
} __attribute__((packed));;


struct perf_sample {
	struct perf_event_header        header;
	struct trace_entry		trace;
	unsigned char			data[0];
} __attribute__((packed));

/* For per CPU perf trace data */
struct perftrace {
	int perf_fd;
	struct perf_event_mmap_page *pc;
	void *data_mmap;
};
typedef struct perftrace perftrace_t;


static struct pevent *pevent = NULL;
GHashTable *pTable = NULL;
static int bufsize = 128;
static perftrace_t ptraces[16];

int sys_perf_event_open(struct perf_event_attr *attr,
                      pid_t pid, int cpu, int group_fd,
                      unsigned long flags)
{
	attr->size = sizeof(*attr);
	return syscall(__NR_perf_event_open, attr, pid, cpu,
			group_fd, flags);
}

char * read_file(const char *file)
{
	char *buffer = NULL; /* quient gcc */
	char buf[4096];
	int len = 0;
	int fd;
	int r;

	fd = open(file, O_RDONLY);
	if (fd < 0)
		exit(-1);

	while((r = read(fd, buf, 4096)) > 0) {
		if (len) {
			char *tmp = (char *)realloc(buffer, len + r + 1);
			if (!tmp)
				free(buffer);
			buffer = tmp;
		} else
			buffer = (char *)malloc(r + 1);
		if (!buffer)
			goto out;
		memcpy(buffer + len, buf, r);
		len += r;
		buffer[len] = '\0';
	}
out:
	return buffer;
}

void parse_event_format(const char *event_name)
{
	char *tptr;
	char *name = strdup(event_name);
	char *sys = strtok_r(name, ":", &tptr);
	char *event = strtok_r(NULL, ":", &tptr);
	char file[256];
	char *buf;
	sprintf(file, "/sys/kernel/debug/tracing/events/%s/%s/format", sys, event);
	buf = read_file(file);
	if (!buf)
		return;
	pevent_parse_event(pevent, buf, strlen(buf), sys);
	free(name);
	free(buf);
}
/*
int parse_event_id(const char *event_name)
{
	char *tptr;
	char *name = strdup(event_name);
	char *sys = strtok_r(name, ":", &tptr);
	char *event = strtok_r(NULL, ":", &tptr);
	char file[256];
	char buf[16];
	int id = -1;

	sprintf(file, "/sys/kernel/debug/tracing/events/%s/%s/id", sys, event);

	FILE *fm;
	char *c;
	int n;

	fm = fopen(file, "r");
	if (!fm) {
		fprintf(stderr, _("Fail to open %s\n"), file);
		return -1;
	}
	n = fread(buf, 1, sizeof(buf), fm);
	if (!n) {
		return -1;
	}
	fclose(fm);
	c = buf;
	id = strtoull(c, NULL, 10);
	free(name);
	return id;
}
*/

void handle_trace_point(void *trace, int cpu, uint64_t time)
{
	struct event_format *event;
	struct pevent_record rec; /* holder */
	unsigned long long val;
	int type;
	int next_pid;
	int wakeups=0;
	rec.data = trace;
	type = pevent_data_type(pevent, &rec);
	event = pevent_find_event(pevent, type);
	if (!event)
		return;
	pevent_get_field_val(NULL,  event, "next_pid", &rec, &val, 0);
	next_pid = (int)val;
	if (next_pid==0)
		return;
	if (g_hash_table_contains(pTable, (gpointer)next_pid)){
		wakeups = (int)g_hash_table_lookup(pTable, (gpointer)next_pid);
		wakeups++;
		g_hash_table_replace(pTable, (gpointer)next_pid, (gpointer)wakeups);
	}
        else
		g_hash_table_insert(pTable, (gpointer)next_pid, (gpointer)1);
}

int collect_wakeups(perftrace_t *pt) {
	struct perf_event_mmap_page *pc = pt->pc;
	struct perf_event_header *header;
	struct perf_sample *sample;
	while (pc->data_tail != pc->data_head ) {
		while (pc->data_tail >= (unsigned int)bufsize*getpagesize())
			pc->data_tail -= bufsize * getpagesize();

		header = (struct perf_event_header *)( (unsigned char *)pt->data_mmap + pc->data_tail);

		if (header->size == 0)
			break;

		pc->data_tail += header->size;

		while (pc->data_tail >= (unsigned int)bufsize * getpagesize())
			pc->data_tail -= bufsize * getpagesize();
		sample = (struct perf_sample *)header;
		if (header->type == PERF_RECORD_SAMPLE)
			handle_trace_point(&sample->data, sample->trace.cpu, sample->trace.time);
	}
	pc->data_tail = pc->data_head;
	return 0;
}

int handle_perf_trace(void)
{
	int i=0;
	for (i=0; i<head->cpunum; i++){
		perftrace_t *pt = ptraces + i;
		collect_wakeups(pt);
	}
//	GList *keys = g_hash_table_get_keys(pTable);
//	GList *item = g_list_first(keys);
//	while (item) {
//		int key = (int)item->data;
//		if (debug)
//			printf("    Process=%d, Wakeups=%d\n", key, (int)g_hash_table_lookup(pTable, (gpointer)key));
//		item = g_list_next(item);
//	}
	return 0;
}

int clear_perf_trace(void) {
	int i;
	for (i=0; i<head->cpunum; i++){ 
		perftrace_t *pt = ptraces + i;
		if (pt->pc){
			munmap((void *)pt->pc, (bufsize + 1)*getpagesize());
			pt->pc = NULL;
		}
		if (pt->perf_fd != -1){
			close(pt->perf_fd);
			pt->perf_fd = -1;
		}
	}
	if (pevent){
		pevent_free(pevent);
		pevent = NULL;
	}
	if (pTable) {
		g_hash_table_destroy(pTable);
		pTable = NULL;
	}
	return 0;
}

static struct perf_event_attr attr;

void init_perf_trace(void) {
	char *evtstr = "sched:sched_switch";
	pevent = pevent_alloc();
	parse_event_format(evtstr);
	memset(&attr, 0, sizeof(attr));
	attr.read_format	= PERF_FORMAT_TOTAL_TIME_ENABLED |
				  PERF_FORMAT_TOTAL_TIME_RUNNING |
				  PERF_FORMAT_ID;

	attr.sample_freq	= 0;
	attr.sample_period	= 1;
	attr.sample_type	|= PERF_SAMPLE_RAW | PERF_SAMPLE_CPU | PERF_SAMPLE_TIME;
	attr.mmap		= 1;
	attr.comm		= 1;
	attr.inherit		= 0;
	attr.disabled		= 1;
	attr.type		= PERF_TYPE_TRACEPOINT;

	attr.config             = pevent->events[0]->id;//parse_event_id(evtstr);
//	attr.config             = parse_event_id(evtstr);
}

int start_perf_trace(void) {
	int ret;
	int i = 0;
	struct {
		__u64 count;
		__u64 time_enabled;
		__u64 time_running;
		__u64 id;
	} read_data;

	if (pTable) 
		g_hash_table_destroy(pTable);
		
	pTable = g_hash_table_new(NULL, NULL);

	for (i=0; i<head->cpunum; i++){
		perftrace_t *pt = ptraces + i;

		if (pt->pc)
			munmap((void *)pt->pc, (bufsize + 1)*getpagesize());

		if (pt->perf_fd != -1)
			close(pt->perf_fd);
		pt->perf_fd = sys_perf_event_open(&attr, -1, i, -1, 0);

		if (pt->perf_fd < 0) {
			fprintf(stderr, "CONFIG_PERF_EVENTS=y\nCONFIG_PERF_COUNTERS=y\nCONFIG_TRACEPOINTS=y\nCONFIG_TRACING=y\n");
			return -1;
		}
		if (read(pt->perf_fd, &read_data, sizeof(read_data)) == -1) {
			perror("Unable to read perf file descriptor\n");
			return -1;
		}
		fcntl(pt->perf_fd, F_SETFL, O_NONBLOCK);

		void *perf_mmap = mmap(NULL, (bufsize + 1)*getpagesize(),
				PROT_READ | PROT_WRITE, MAP_SHARED, pt->perf_fd, 0);
		if (perf_mmap == MAP_FAILED) {
			fprintf(stderr, "failed to mmap with %d (%s)\n", errno, strerror(errno));
			return -1;
		}	
	
		pt->pc = (struct perf_event_mmap_page *)perf_mmap;
		pt->data_mmap = (unsigned char *)perf_mmap + getpagesize();

		ret = ioctl(pt->perf_fd, PERF_EVENT_IOC_ENABLE);
		if (ret < 0) {
			fprintf(stderr, "failed to enable perf \n");
			return -1;
		}
	} 
	return 0;
}


int stop_perf_trace(void) {
	int ret;
	int i = 0;
	for (i=0; i<head->cpunum; i++){ 
		perftrace_t *pt = ptraces + i;
		ret = ioctl(pt->perf_fd, PERF_EVENT_IOC_DISABLE);
		if (ret < 0) 
			fprintf(stderr, "failed to enable perf \n");
	}
	return 0;
}


