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
 */

#define _GNU_SOURCE
#include "sysmon.h"

frame_t *bf = NULL;

static int compare_cpu(gconstpointer a, gconstpointer b)
{
	sum_pdata_t *A = (sum_pdata_t *) a;
	sum_pdata_t *B = (sum_pdata_t *) b;

	return B->cpu_delta - A->cpu_delta;
}

static int compare_wakeups(gconstpointer a, gconstpointer b)
{
	sum_pdata_t *A = (sum_pdata_t *) a;
	sum_pdata_t *B = (sum_pdata_t *) b;

	return B->wakeups_total - A->wakeups_total;
}


static int compare_rss(gconstpointer a, gconstpointer b)
{
	sum_pdata_t *A = (sum_pdata_t *) a;
	sum_pdata_t *B = (sum_pdata_t *) b;

	return B->rss_total - A->rss_total;
}


sum_pdata_t *new_process(pdata_t * d, sysnode_t *s)
{
	sum_pdata_t *spd = malloc(sizeof(sum_pdata_t));
	pdata_t *d_base = (pdata_t *)g_hash_table_lookup(bf->dTable, (gpointer)d->pid);
	if (d_base) {
		spd->cpu_0 = d_base->cpu;
	}else {	
		spd->cpu_0 = 0;
		printf("New process %llu\n", d->cpu);
	}
	spd->cpu_delta = d->cpu - spd->cpu_0;
	spd->cpu_max = 0;
	spd->rss_total = d->rss;
	spd->pid = d->pid;
	spd->tlist = NULL;
	spd->wakeups_total = d->wakeups;
	pnode_t *n = (pnode_t *) malloc(sizeof(pnode_t));
	n->wakeups = d->wakeups;
	n->rss = d->rss;
	n->wakeups = d->wakeups;
	n->s = s;
	n->cpu_delta = d->cpu - spd->cpu_0;	
	if (n->cpu_delta > spd->cpu_max)
		spd->cpu_max = n->cpu_delta;
	spd->tlist = g_list_append(spd->tlist, n);

	strncpy(spd->pname, d->pname, PNAME_LENGTH);
	return spd;
}

int do_sort(sum_block_t * sbk, char *type)
{
	if (strcmp(type, "cpu") == 0) {
		sbk->pdlist = g_list_sort(sbk->pdlist, compare_cpu);
		return 0;
	}
	if (strcmp(type, "rss") == 0) {
		sbk->pdlist = g_list_sort(sbk->pdlist, compare_rss);
		return 0;
	}
	if (strcmp(type, "wakeups") == 0) {
		sbk->pdlist = g_list_sort(sbk->pdlist, compare_wakeups);
		return 0;
	}
	printf("No %s sort type\n", type);
	return -1;
}

int do_sum(sum_block_t * sbk)
{
	frame_t *f = NULL, *prev = NULL;
	int i = 0;
	GHashTable *fTable = g_hash_table_new(NULL, NULL);
	bf = head->bframe;
	sbk->id_0 = bf->id;
	sbk->tot_0 = bf->tot;
	if (encpuidle) {
		sbk->wakeup_0 = bf->wakeup;
		sbk->wakeup_delta = 0;
	}
	prev = bf;
	FOR_EACH_FRM(f) {
			sbk->id_delta = f->id - sbk->id_0;
			sbk->tot_delta = f->tot - sbk->tot_0;

			sysnode_t *s = &sbk->sa[FRMNO(f)];
			s->idle_delta = f->id - prev->id;
			s->clock = f->tot - prev->tot;

			if (encpuidle){
				sbk->wakeup_delta = f->wakeup - sbk->wakeup_0;
				s->wakeup_delta = f->wakeup - prev->wakeup;
			}

			if (encpufreq) {
				int k;
				for (k = 0; k < maxpstat; k++)
					s->freq_delta[k] = f->freq[k] -  prev->freq[k];
			}
		
			/* Go through known processes one by one */
			GList *pitem = g_list_first(sbk->pdlist);
			while(pitem) {
				sum_pdata_t *spd = (sum_pdata_t *) pitem->data;
				pnode_t *n = (pnode_t *) malloc(sizeof(pnode_t));
				n->wakeups = 0;
				n->s = s;
				n->cpu_delta = 0;	
				GList *last = g_list_last(spd->tlist);
				if (last){
					pnode_t *n0 = (pnode_t *)last->data;
					n->rss = n0->rss;
				}
				pdata_t *d = g_hash_table_lookup(f->dTable, (gpointer)spd->pid);
				if (d) {
					frame_t *lf = NULL;
					int fno = (int)g_hash_table_lookup(fTable, (gpointer)spd->pid);
					lf = head->frames + fno;
					pdata_t *d0 = g_hash_table_lookup(lf->dTable, (gpointer)spd->pid);
					spd->cpu_delta = d->cpu - spd->cpu_0;
					spd->wakeups_total += d->wakeups;	
					n->rss = d->rss;
					n->cpu_delta =
						(d0) ? d->cpu - d0->cpu : 0;
					n->wakeups = d->wakeups;
					if (n->cpu_delta > spd->cpu_max)
						spd->cpu_max = n->cpu_delta;
					g_hash_table_insert(fTable, (gpointer)d->pid, (gpointer)(FRMNO(f)));
				}
				spd->rss_total += n->rss;
				spd->tlist = g_list_append(spd->tlist, n);
				pitem = g_list_next(pitem);
			}

			/* Handle new process */
			GList *vals = g_hash_table_get_values(f->dTable);
			GList *item = g_list_first(vals);
			while (item) {
				pdata_t *d = (pdata_t *)item->data;
				if (!g_hash_table_lookup(fTable, (gpointer)d->pid)) {
					sum_pdata_t *spd = new_process(d, s);
					sbk->pdlist =
						g_list_append(sbk->pdlist, spd);
					g_hash_table_insert(fTable, (gpointer)d->pid, (gpointer)(FRMNO(f)));
				}
		
				item = g_list_next(item);
			}
	
		prev = f;
	}
	g_hash_table_destroy(fTable);

	printf("\n********************************************\n");
	printf("cpunum=%d\n", head->cpunum);
	printf("idle=%4.1f%%\n", 
	       (double) sbk->id_delta * 100 / (double) sbk->tot_delta);
	if (encpuidle)
		printf("wakeup=%3.1f/s\n", sbk->wakeup_delta * 1.0 / head->len / head->delay);

	if (debug) {
		for (i = 0; i < head->len - 1 ; i++) {
			sysnode_t *s = &sbk->sa[i];
			printf("\t[%llu]%llu", s->clock, s->idle_delta);
			if (encpuidle)
				printf(",%llu", s->wakeup_delta);
	
			if (encpufreq){
				uint64_t freq_tot = 0;
				int k;
				for (k = 0; k < maxpstat; k++)
					freq_tot += s->freq_delta[0];
				printf(",%llu/%llu", s->freq_delta[0], freq_tot);
			}
			printf("--->");
		}
	}
	printf("\n");
	printf("\n******************CPU Usage**************************\n");
	do_sort(sbk, "cpu");
	GList *item = g_list_first(sbk->pdlist);
	while (item) {
		sum_pdata_t *spd = item->data;
		double cpu_usage = (double) spd->cpu_delta * 100 / (double) sbk->tot_delta;
		if (cpu_usage >= 0.1){ 
			printf
		    	("Process(%-16s),  cpu=%4.1f%%,  pid=%u\n",
		     	spd->pname, cpu_usage, spd->pid);
		}	

		if (debug) {
			if (spd->cpu_delta > 0) {
				GList *node = g_list_first(spd->tlist);
				while (node) {
					pnode_t *n = node->data;
					printf("\t[%llu]%llu,%u--->",
					       		n->s->clock, n->cpu_delta,
					       		n->rss);
					node = g_list_next(node);
				}
				printf("\n");
			}
		}
		item = g_list_next(item);
	}

	printf("\n");
	printf("\n******************CPU Wakeups**************************\n");
	do_sort(sbk, "wakeups");
	item = g_list_first(sbk->pdlist);
	while (item) {
		sum_pdata_t *spd = item->data;
		double wakeups = (double)spd->wakeups_total/head->len/(double)head->delay;
		if (wakeups >= 0.1) 
			printf
		    	("Process(%-16s),  wakeups=%6.1f/s,  pid=%u\n",
		     	spd->pname, wakeups, spd->pid);
		if (debug) {
			if (spd->cpu_delta > 0) {
				GList *node = g_list_first(spd->tlist);
				while (node) {
					pnode_t *n = node->data;
					printf("\t[%llu]%llu,%u--->",
					       		n->s->clock, n->cpu_delta,
					       		n->rss);
					node = g_list_next(node);
				}
				printf("\n");
			}
		}
		item = g_list_next(item);
	}
	printf("\n*************************End****************************\n");
	return 0;
}
