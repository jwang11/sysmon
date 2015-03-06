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
int store_info(char *fname)
{
	char str[128];
	xmlDocPtr doc = xmlNewDoc(BAD_CAST "1.0");
	xmlNodePtr root = xmlNewNode(NULL, BAD_CAST "sysmon");
	xmlDocSetRootElement(doc, root);
	xmlNodePtr header, body, frame, cpu, mem, power, cpufreq, pinfo, process;

	header = xmlNewNode(NULL, BAD_CAST "header");
	xmlAddChild(root, header);
	sprintf(str, "%d", head->delay);
	xmlNewChild(header, NULL, BAD_CAST "delay", BAD_CAST str);
	sprintf(str, "%d", head->count);
	xmlNewChild(header, NULL, BAD_CAST "count", BAD_CAST str);
	sprintf(str, "%d", head->len);
	xmlNewChild(header, NULL, BAD_CAST "len", BAD_CAST str);
	sprintf(str, "%d", head->maxcstat);
	xmlNewChild(header, NULL, BAD_CAST "maxctat", BAD_CAST str);
	sprintf(str, "%d", head->maxpstat);
	xmlNewChild(header, NULL, BAD_CAST "maxptat", BAD_CAST str);
	sprintf(str, "%d", head->cpunum);
	xmlNewChild(header, NULL, BAD_CAST "cpunumber", BAD_CAST str);
	sprintf(str, "%ld", head->tv.tv_sec);
	xmlNewChild(header, NULL, BAD_CAST "time", BAD_CAST str);

	body = xmlNewNode(NULL, BAD_CAST "body");
	xmlAddChild(root, body);

	frame_t *f = NULL;

	if (debug) 
		printf("the count is : %d \n", head->count);
	
	FOR_EACH_FRM(f) {
		frame = xmlNewNode(NULL, BAD_CAST "frame");
		xmlAddChild(body, frame);

		sprintf(str, "%d", FRMNO(f));
		xmlNewProp(frame, BAD_CAST "id",
				   BAD_CAST str);

		cpu = xmlNewNode(NULL, BAD_CAST "cpu");
		xmlAddChild(frame, cpu);

		sprintf(str, "%llu", f->id);
		xmlNewChild(cpu, NULL, BAD_CAST "idletick", BAD_CAST str);

		sprintf(str, "%llu", f->tot);
		xmlNewChild(cpu, NULL, BAD_CAST "totaltick", BAD_CAST str);


		mem = xmlNewNode(NULL, BAD_CAST "mem");
		xmlAddChild(frame, mem);

		sprintf(str, "%llu", f->free);
		xmlNewChild(mem, NULL, BAD_CAST "free", BAD_CAST str);

		sprintf(str, "%llu", f->buff);
		xmlNewChild(mem, NULL, BAD_CAST "buffer", BAD_CAST str);

		sprintf(str, "%llu", f->cache);
		xmlNewChild(mem, NULL, BAD_CAST "cache", BAD_CAST str);

		power = xmlNewNode(NULL, BAD_CAST "power");
		xmlAddChild(frame, power);
		if (encpuidle){
			sprintf(str, "%llu", f->wakeup);
			xmlNewChild(power, NULL, BAD_CAST "wakeup", BAD_CAST str);
		}

		int i = 0;
		if (encpufreq) {
			for (i = 0; i < maxpstat; i++) {
				sprintf(str, "%llu", f->freq[i]);
				cpufreq = xmlNewChild(power, NULL, BAD_CAST "cpufreq", BAD_CAST str);
				sprintf(str, "%d", i);
				xmlNewProp(cpufreq, BAD_CAST "level",
				   	BAD_CAST str);
			
			}
		}
		//sprintf(str, "%u", f->freq);
		//xmlNewChild(power, NULL, BAD_CAST "cpufreq", BAD_CAST str);

		pinfo = xmlNewNode(NULL, BAD_CAST "processinfo");
		xmlAddChild(frame, pinfo);
		sprintf(str, "%u", f->pnum);
		xmlNewProp(pinfo, BAD_CAST "number",
	   		BAD_CAST str);
	
		GList *vals = g_hash_table_get_values(f->dTable);
		GList *item = g_list_first(vals);
		while (item) {
			pdata_t *d = (pdata_t *)item->data;
			process = xmlNewNode(NULL, BAD_CAST "process");
			xmlAddChild(pinfo, process);
			xmlNewProp(process, BAD_CAST "name",
				   BAD_CAST d->pname);
			sprintf(str, "%d", d->pid);
			xmlNewProp(process, BAD_CAST "pid", BAD_CAST str);

			sprintf(str, "%llu", d->cpu);
			xmlNewChild(process, NULL, BAD_CAST "cputick",
				    BAD_CAST str);
			sprintf(str, "%u", d->rss);
			xmlNewChild(process, NULL, BAD_CAST "rss",
				    BAD_CAST str);
			item = g_list_next(item);
		}
	}
	xmlSaveFormatFileEnc(fname, doc, "UTF-8", 1);

	xmlFreeDoc(doc);
	xmlCleanupParser();
	return 0;
}

int store_result_by_sys_wakeups(sum_block_t * sbk, char *fname)
{
	int i;
	int ret = 0;

	/* Create result template */
	char *f = (fname ? fname : DEFAULT_SYSMON_SYSWAKEUPS_FILE);
	FILE *fd = fopen(f, "w");
	if (!fd) {
		fprintf(stderr, _("Fail open file"));
		return 1;
	}
	fprintf(fd, "<html>\n");
	fprintf(fd, "  <head>\n");
	fprintf(fd,
		"    <script type=\"text/javascript\" src=\"https://www.google.com/jsapi\"></script>\n");
	fprintf(fd, "    <script type=\"text/javascript\">\n");
	fprintf(fd,
		"      google.load(\"visualization\", \"1\", {packages:[\"corechart\"]});\n");
	fprintf(fd, "      google.setOnLoadCallback(drawChart);\n");

	fprintf(fd, "      function drawChart() {\n");
	fprintf(fd,
		"        var data = new google.visualization.DataTable();\n");
	fprintf(fd, "        data.addColumn('string', 'Time');\n");
	float wakeup = sbk->wakeup_delta * 1.0/head->len/head->delay;
	fprintf(fd, "        data.addColumn('number', 'Wakeup(%3.1f)');\n", wakeup);
	fprintf(fd, "\n");


	i = 0;
	while (i < head->len){
		sysnode_t *s = &sbk->sa[i];
		fprintf(fd, "        data.addRow([\"%d\", %3.1f]);\n", i+1, s->wakeup_delta * 1.0/head->delay);
		i++;
	}

	fprintf(fd,
		"        var chart = new google.visualization.LineChart(document.getElementById('chart_div'));\n");
	char fmt[64];
	strftime(fmt, sizeof(fmt), "%Y-%m-%d %H:%M", localtime(&head->tv.tv_sec));
	fprintf(fd,
		"        chart.draw(data, {width: 1024, height: 600, title: 'Wakeup (%s, sampling %d by %ds)'});\n", fmt, head->len - 1, head->delay );
	fprintf(fd, "    }\n");
	fprintf(fd, "    </script>\n  </head>\n");
	fprintf(fd, "  <body>\n");
	fprintf(fd, "    <div id=\"chart_div\"></div>\n");
	fprintf(fd, "  </body>\n</html>\n");

	return ret;
}


int store_result_by_cpu_freq(sum_block_t * sbk, char *fname)
{
	int i;
	int ret = 0;

	/* Create result template */
	char *f = (fname ? fname : DEFAULT_SYSMON_CPUFREQ_FILE);
	FILE *fd = fopen(f, "w");
	if (!fd) {
		fprintf(stderr, _("Fail open file"));
		return 1;
	}
	fprintf(fd, "<html>\n");
	fprintf(fd, "  <head>\n");
	fprintf(fd,
		"    <script type=\"text/javascript\" src=\"https://www.google.com/jsapi\"></script>\n");
	fprintf(fd, "    <script type=\"text/javascript\">\n");
	fprintf(fd,
		"      google.load(\"visualization\", \"1\", {packages:[\"corechart\"]});\n");
	fprintf(fd, "      google.setOnLoadCallback(drawChart);\n");

	fprintf(fd, "      function drawChart() {\n");
	fprintf(fd,
		"        var data = new google.visualization.DataTable();\n");
	fprintf(fd, "        data.addColumn('string', 'Time');\n");
	for (i = 0; i < maxpstat; i++)
		fprintf(fd, "        data.addColumn('number', 'Freq%d');\n", i);

	fprintf(fd, "\n");


	i = 0;
	while (i < head->len){
		sysnode_t *s = &sbk->sa[i];
		uint64_t freq_tot = 0;
		int j;

		for (j = 0; j < maxpstat; j++)
			freq_tot += s->freq_delta[j];
		 
		float factor = 100.0 / freq_tot;

		fprintf(fd, "        data.addRow([\"%d\"", i + 1);
		for (j = 0; j < maxpstat; j++)
			fprintf(fd, ", %3.1f", s->freq_delta[j] * factor);
		fprintf(fd, "]);\n");  
		fprintf(fd, "\n");
		i++;
	}

	fprintf(fd,
		"        var chart = new google.visualization.LineChart(document.getElementById('chart_div'));\n");
	char fmt[64];
	strftime(fmt, sizeof(fmt), "%Y-%m-%d %H:%M", localtime(&head->tv.tv_sec));

	fprintf(fd,
		"        chart.draw(data, {width: 1024, height: 600, title: 'CPU Frequency (%s, sampling %d by %ds)', vAxis: {maxValue: 100}});\n", fmt, head->len, head->delay);
	fprintf(fd, "    }\n");
	fprintf(fd, "    </script>\n  </head>\n");
	fprintf(fd, "  <body>\n");
	fprintf(fd, "    <div id=\"chart_div\"></div>\n");
	fprintf(fd, "  </body>\n</html>\n");

	return ret;
}


int store_result_by_rss(sum_block_t * sbk, char *fname)
{
	int i;
	int ret = 0;

	if ( (ret = do_sort(sbk, "rss")) != 0)
		return ret;

	/* Create result template */

	char *f = (fname ? fname : DEFAULT_SYSMON_RSS_FILE);
	FILE *fd = fopen(f, "w");
	if (!fd) {
		fprintf(stderr, _("Fail open file"));
		return 1;
	}
	fprintf(fd, "<html>\n");
	fprintf(fd, "  <head>\n");
	fprintf(fd,
		"    <script type=\"text/javascript\" src=\"https://www.google.com/jsapi\"></script>\n");
	fprintf(fd, "    <script type=\"text/javascript\">\n");
	fprintf(fd,
		"      google.load(\"visualization\", \"1\", {packages:[\"corechart\"]});\n");
	fprintf(fd, "      google.setOnLoadCallback(drawChart);\n");

	fprintf(fd, "      function drawChart() {\n");
	fprintf(fd,
		"        var data = new google.visualization.DataTable();\n");
	fprintf(fd, "        data.addColumn('string', 'Time');\n");
	fprintf(fd, "\n");

	int k = 1;		/* Fix colume number */
	

	i = 0;
	while (i < head->len){
		fprintf(fd, "        data.addRow([\"%d\"])\n", i + 1);
		i++;
	}

	GList *item = g_list_first(sbk->pdlist);
	while (item) {
		sum_pdata_t *spd = item->data;

		/* Filter out small */
		if (spd->rss_total/head->len < 2000)
			break;
		fprintf(fd, "        data.addColumn('number', '%s(%lluK)');\n",
			spd->pname, spd->rss_total/head->len);
		GList *node = spd->tlist;
		while (node) {
			pnode_t *n = node->data;
			int start = n->s - sbk->sa;

			fprintf(fd, "        data.setValue(%d, %d, %u);\n",
				start, k, n->rss);
			node = g_list_next(node);
		}
		fprintf(fd, "\n");
		item = g_list_next(item);
		k++;
	}

	fprintf(fd,
		"        var chart = new google.visualization.LineChart(document.getElementById('chart_div'));\n");

	char fmt[64];
	strftime(fmt, sizeof(fmt), "%Y-%m-%d %H:%M", localtime(&head->tv.tv_sec));
	fprintf(fd,
		"        chart.draw(data, {width: 1024, height: 600, title: 'Memory Footprint (%s, sampling %d by %ds)'});\n", fmt, head->len , head->delay);
	fprintf(fd, "    }\n");
	fprintf(fd, "    </script>\n  </head>\n");
	fprintf(fd, "  <body>\n");
	fprintf(fd, "    <div id=\"chart_div\"></div>\n");
	fprintf(fd, "  </body>\n</html>\n");

	return ret;
}

int store_result_by_cpu_usage(sum_block_t * sbk, char *fname)
{
	int i;
	int ret = 0;

	if ((ret = do_sort(sbk, "cpu")) != 0)
		return ret;

	char *f = fname ? fname : DEFAULT_SYSMON_CPUUSAGE_FILE;
	FILE *fd = fopen(f, "w");
	if (!fd) {
		fprintf(stderr, _("Fail open file"));
		return 1;
	}
	fprintf(fd, "<html>\n");
	fprintf(fd, "  <head>\n");
	fprintf(fd,
		"    <script type=\"text/javascript\" src=\"https://www.google.com/jsapi\"></script>\n");
	fprintf(fd, "    <script type=\"text/javascript\">\n");
	fprintf(fd,
		"      google.load(\"visualization\", \"1\", {packages:[\"corechart\"]});\n");
	fprintf(fd, "      google.setOnLoadCallback(drawChart);\n");

	fprintf(fd, "      function drawChart() {\n");
	fprintf(fd,
		"        var data = new google.visualization.DataTable();\n");
	fprintf(fd, "        data.addColumn('string', 'Time');\n");
	fprintf(fd, "        data.addColumn('number', 'Idle(%3.1f)');\n", sbk->id_delta * 100.0 / sbk->tot_delta);
	fprintf(fd, "\n");

	int k = 2;		/* Fix colume number */
	i = 0;
	while (i < head->len){
		sysnode_t *s = &sbk->sa[i];
		float factor = 100.0 / s->clock;
		fprintf(fd, "        data.addRow([\"%d\", %3.1f])\n", i + 1,
			s->idle_delta * factor);

		i++;
	}

	fprintf(fd, "\n");
	GList *item = g_list_first(sbk->pdlist);
	while (item) {
		sum_pdata_t *spd = item->data;
		/* filter out inactive processes */
		if (spd->cpu_max < 3) {
			item = g_list_next(item);
			continue;
		}
		fprintf(fd, "        data.addColumn('number', '%s(%3.1f)');\n",
			spd->pname, spd->cpu_delta * 100.0 /sbk->tot_delta);
		GList *node = spd->tlist;
		while (node) {
			pnode_t *n = node->data;
			int start = n->s - sbk->sa;
			float factor = 100.0 / n->s->clock;

			/* Sometimes there is strange Spike data */
			uint64_t val =
			    (n->cpu_delta >
			     n->s->clock) ? n->s->clock : n->cpu_delta;
			fprintf(fd,
				"        data.setValue(%d, %d, %3.1f);\n",
				start, k, val * factor);
			node = g_list_next(node);
		}
		fprintf(fd, "\n");
		item = g_list_next(item);
		k++;
	}

	fprintf(fd,
		"        var chart = new google.visualization.LineChart(document.getElementById('chart_div'));\n");

	char fmt[64];
	strftime(fmt, sizeof(fmt), "%Y-%m-%d %H:%M", localtime(&head->tv.tv_sec));
	fprintf(fd,
		"        chart.draw(data, {width: 1024, height: 600, title: 'CPU Usage (%s, sampling %d by %ds)', vAxis: {maxValue: 100}});\n", fmt, head->len, head->delay);
	fprintf(fd, "    }\n");
	fprintf(fd, "    </script>\n  </head>\n");
	fprintf(fd, "  <body>\n");
	fprintf(fd, "    <div id=\"chart_div\"></div>\n");
	fprintf(fd, "  </body>\n</html>\n");

	return ret;
}

int store_result_by_process_wakeups(sum_block_t * sbk, char *fname)
{
	int i;
	int ret = 0;

	if ( (ret = do_sort(sbk, "wakeups")) != 0)
		return ret;

	/* Create result template */

	char *f = (fname ? fname : DEFAULT_SYSMON_PROCESSWAKEUPS_FILE);
	FILE *fd = fopen(f, "w");
	if (!fd) {
		fprintf(stderr, _("Fail open file"));
		return 1;
	}
	fprintf(fd, "<html>\n");
	fprintf(fd, "  <head>\n");
	fprintf(fd,
		"    <script type=\"text/javascript\" src=\"https://www.google.com/jsapi\"></script>\n");
	fprintf(fd, "    <script type=\"text/javascript\">\n");
	fprintf(fd,
		"      google.load(\"visualization\", \"1\", {packages:[\"corechart\"]});\n");
	fprintf(fd, "      google.setOnLoadCallback(drawChart);\n");

	fprintf(fd, "      function drawChart() {\n");
	fprintf(fd,
		"        var data = new google.visualization.DataTable();\n");
	fprintf(fd, "        data.addColumn('string', 'Time');\n");
	fprintf(fd, "\n");

	int k = 1;		/* Fix colume number */
	

	i = 0;
	while (i < head->len){
		fprintf(fd, "        data.addRow([\"%d\"])\n", i + 1);
		i++;
	}

	GList *item = g_list_first(sbk->pdlist);
	while (item) {
		sum_pdata_t *spd = item->data;

		/* Filter out small */
		if ((double)spd->wakeups_total/head->len < 0.2 )
			break;
		fprintf(fd, "        data.addColumn('number', '%s(%5.1llu/s)');\n",
			spd->pname, spd->wakeups_total/head->len/head->delay);
		GList *node = spd->tlist;
		while (node) {
			pnode_t *n = node->data;
			int start = n->s - sbk->sa;

			fprintf(fd, "        data.setValue(%d, %d, %u);\n",
				start, k, n->wakeups / head->delay);
			node = g_list_next(node);
		}
		fprintf(fd, "\n");
		item = g_list_next(item);
		k++;
	}

	fprintf(fd,
		"        var chart = new google.visualization.LineChart(document.getElementById('chart_div'));\n");

	char fmt[64];
	strftime(fmt, sizeof(fmt), "%Y-%m-%d %H:%M", localtime(&head->tv.tv_sec));
	fprintf(fd,
		"        chart.draw(data, {width: 1024, height: 600, title: 'Process Wakeups (%s, sampling %d by %ds)'});\n", fmt, head->len,  head->delay);
	fprintf(fd, "    }\n");
	fprintf(fd, "    </script>\n  </head>\n");
	fprintf(fd, "  <body>\n");
	fprintf(fd, "    <div id=\"chart_div\"></div>\n");
	fprintf(fd, "  </body>\n</html>\n");

	return ret;

}
