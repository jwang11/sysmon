/*
 * Copyright (C) 2010 Intel Corporation
 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

 * Authors:
 *    Wang, Jing <jing.j.wang@intel.com>                                                                               
 *    Chen, Guobing <guobing.chen@intel.com>
 */


#define _GNU_SOURCE
#include "sysmon.h"

/* Global variables */
int delay = DEFAULT_SYSMON_DURATION;
int count = DEFAULT_SYSMON_FRAME_COUNT;
int maxcstat = 0;
int maxpstat = 0;
int encpuidle = _FALSE;
int encpufreq = _FALSE;
int debug = _FALSE;
header_t *head = NULL;
header_t hdr;

sum_block_t bk;
flag_t sysflag;

procinfo_t *sysinfo;
int stopflag = 0;

void free_frame(frame_t *f) {
	if (! f->dTable)
		return;
	GList *keys = g_hash_table_get_keys(f->dTable);
	GList *item = g_list_first(keys);
	while (item) {
		int key = (int)item->data;
		pdata_t *d = (pdata_t *)g_hash_table_lookup(f->dTable, (gpointer)key);
		if (d)
			free(d);
		item = g_list_next(item);
	}
	g_hash_table_destroy(f->dTable);

}

void free_sumblock(void) {
	if (bk.sa)
		free(bk.sa);
	
	GList *l = g_list_first(bk.pdlist);
	while (l) {
		sum_pdata_t *spd = l->data;
		GList *t = spd->tlist;
		while (t) {
			if (t->data)
				free(t->data);
			t = g_list_next(t);
		}
		g_list_free(spd->tlist);
		free(spd);
		l = g_list_next(l);
	}
	g_list_free(bk.pdlist);
}

void cleanup(void)
{
	clear_perf_trace();
	free_sumblock();

	frame_t *f;
	FOR_EACH_FRM(f) {
		free_frame(f);
	}
	free_frame(head->bframe);

	if (head->bframe)
		free(head->bframe);

	if (sysinfo)
		free(sysinfo);
}

void usage()
{
	printf(_("Usage: sysmon [OPTION...]\n"));
	printf(_
	       ("  -o, --log=File                               Output the app use into specified file\n"));
	printf(_
	       ("  -d, --delay=Second                              Specify delay time. default %d\n"),
	       delay);
	printf(_
	       ("  -c, --count=Number                              Specify times, default %d\n"),
	       count);
	printf(_
	       ("  -w, --wakeup                              	   Enable wakeup\n"));
	printf(_
	       ("  -f, --cpufreq                          	   Enable cpufreq\n"));
	printf(_
	       ("  -x, --debug                                     Specify to show more info to stdout, default false\n"));
	printf(_
	       ("  -h, --help                                      Show this help message\n"));

	exit(0);
}

void sighandler (int signum, siginfo_t *info, void *ptr) {
	printf("Received signal %d\n", signum);
	printf("Signal come from process %u\n", info->si_pid);
	stopflag = 1;	
}

int sysmon_init(void)
{
	struct sigaction act;
	memset(&act, 0 , sizeof(act));
	act.sa_sigaction = sighandler;
	act.sa_flags = SA_SIGINFO;

	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);


        uint32_t t_pnum = 0;
        get_process_num(&t_pnum);
        int maxprocessnum = t_pnum + MAX_NEW_PNUM;
        printf("\tcount = %d, delay = %d, max_pnum=%d\n", count, delay, maxprocessnum);
        sysinfo = (procinfo_t *) malloc(sizeof(procinfo_t) + maxprocessnum * sizeof(pinfo_t));

	char buf[1024], *c;
	FILE *fd;
	maxcstat = 0;

	/* cpuidle flag check */
	DIR *cpudir = opendir("/sys/devices/system/cpu/cpu0/cpuidle");
	if (!cpudir) {
		sysflag.cpuidle = 0;
		maxcstat = 0;
	} else {
		struct dirent *entry;
		sysflag.cpuidle = 1;
		while ((entry = readdir(cpudir)) != 0) {
			if (strlen(entry->d_name) < 3)
				continue;
			if (!isdigit(entry->d_name[5]))
				continue;
			maxcstat++;
		}
	}
	closedir(cpudir);

	/* cpufreq flag check */
	cpudir = opendir("/sys/devices/system/cpu/cpu0/cpufreq/stats");
	if (!cpudir)
		sysflag.cpufreq = 0;
	else{
		sysflag.cpufreq = 1;
		fd = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_available_frequencies", "r");
		maxpstat = 0;
		size_t n = fread(buf, 1, sizeof(buf), fd);
		if (n<=0)
			return 1;
		char *str = buf;
		while ((str = strstr(str, " ")) != NULL) {
			str++;
			maxpstat++;
		}
		fclose(fd);
	}
	printf(_("\tmaxpstat = %d, maxcstat = %d\n"), maxpstat, maxcstat);
	closedir(cpudir);

        /* meminfo check */
	fd = fopen("/proc/meminfo", "r");
	if (!fd)
		return 1;
	size_t n = fread(buf, 1, sizeof(buf), fd);
	if (n<=0)
		return 1;
	fclose(fd);
	c = strstr(buf, "MemTotal");
	c += 10;		/* 8 + 2 */
	head->totalmem = strtoull(c, NULL, 10);
	if (debug)
		printf(_
		       ("Basic config: count=%d, delay=%d, maxcstat=C%d\n"),
		       count, delay, maxcstat);

	int frmsize = sizeof(frame_t);
	frame_t *f = (frame_t *) malloc(frmsize * (count + 1));
	if (!f) {
		fprintf(stderr, _("Fail to allocate frame_t"));
		return 1;
	}
	memset(f, 0, frmsize * (count + 1));
	printf("\tPre allocate %u B memory, One frame has %u B\n", frmsize * count, frmsize);

	head->bframe = f;
	head->frames = f + 1;
	head->maxcstat = maxcstat;
	head->maxpstat = maxpstat;
	head->count = count;
	head->delay = delay;
	head->cpunum = sysconf(_SC_NPROCESSORS_ONLN);
	head->top = 0;
	head->tail = 0;
	gettimeofday(&(head->tv), NULL);

	int sysnodesize = sizeof(sysnode_t) * (head->count - 1);
	bk.sa = (sysnode_t *) malloc(sysnodesize);
	memset(bk.sa, 0, sysnodesize);
	init_perf_trace();
	return 0;
}

int main(int argc, char **argv)
{
	frame_t *f = NULL;
	char logname[128];
	char *logdir = DEFAULT_SYSMON_LOGDIR;

	head = &hdr;
	setlocale(LC_ALL, "");
	bindtextdomain("sysmon", "/usr/share/locale");
	textdomain("sysmon");
	if (argc < 0 && argv[0] == NULL)
		return EXIT_FAILURE;

	while (1) {
		static struct option opts[] = {
			{"output", 1, NULL, 'o'},
			{"delay", 1, NULL, 'd'},
			{"count", 1, NULL, 'c'},
			{"debug", 0, NULL, 'x'},
			{"wakeup", 0, NULL, 'w'},
			{"cpufreq", 0, NULL, 'f'},
			{"help", 0, NULL, 'h'},
			{0, 0, NULL, 0}
		};
		int index2 = 0, c;

		c = getopt_long(argc, argv, "o:d:p:c:xwflh", opts, &index2);
		if (c == -1)
			break;
		switch (c) {
		case 'o':
			logdir = optarg;
			break;
		case 'd':
			delay = atoi(optarg);
			break;
		case 'c':
			count = atoi(optarg);
			break;
		case 'x':
			debug = _TRUE;
			break;
		case 'w':
			encpuidle = _TRUE;
			break;
		case 'f':
			encpufreq = _TRUE;
			break;
		case 'h':
			usage();
			break;
		default:;
		}
	}

	if (count < 2) {
		fprintf(stderr, _("count must be larger than 1\n"));
		return EXIT_FAILURE;
	}	

	if (delay < 1) {
		fprintf(stderr, _("delay must be larger than 0\n"));
		return EXIT_FAILURE;
	}
	
	if (logdir) {
                DIR *dir = opendir(logdir);
		if (!dir){
			fprintf(stderr, _("Specify error log dir\n"));
			return EXIT_FAILURE;
		}
	}

	if (sysmon_init() == 1) {
		fprintf(stderr, _("sysmon_init fail\n"));
		return EXIT_FAILURE;
	}

	printf(_("\tStart sampling\n"));

	read_info(1);
	calc_info(head->bframe);
	
	while (!stopflag) {
		start_perf_trace();
		sleep(delay);
		stop_perf_trace();
		NEWFRM(f)
		handle_perf_trace();
		if (read_info(0))
			break;
		calc_info(f);
		if ( FRMLEN() >= (count-1))
			break;
	}

	head->len = FRMLEN();
	printf("\ntop=%d, tail=%d len=%d\n", head->top, head->tail, head->len);
	if (head->len < 2) {
		printf("Too few samples, ignore it\n");
		return EXIT_FAILURE;	
	}
	snprintf(logname, sizeof(logname), "%s/%s", logdir, DEFAULT_SYSMON_DATA_FILE);
	store_info(logname);

	do_sum(&bk);
	snprintf(logname, sizeof(logname), "%s/%s", logdir, DEFAULT_SYSMON_CPUUSAGE_FILE);
	store_result_by_cpu_usage(&bk, logname);
	snprintf(logname, sizeof(logname), "%s/%s", logdir, DEFAULT_SYSMON_RSS_FILE);
	store_result_by_rss(&bk, logname);
	snprintf(logname, sizeof(logname), "%s/%s", logdir, DEFAULT_SYSMON_PROCESSWAKEUPS_FILE);
	store_result_by_process_wakeups(&bk, logname);

	if (encpufreq){
	        snprintf(logname, sizeof(logname), "%s/%s", logdir, DEFAULT_SYSMON_CPUFREQ_FILE);
		store_result_by_cpu_freq(&bk, NULL);
	}

	if (encpuidle){
	        snprintf(logname, sizeof(logname), "%s/%s", logdir, DEFAULT_SYSMON_SYSWAKEUPS_FILE);
		store_result_by_sys_wakeups(&bk, NULL);
	}
	cleanup();
	return EXIT_SUCCESS;
}
