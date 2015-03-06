CFLAGS += -O2 -g -Wall `pkg-config --cflags --libs glib-2.0 libxml-2.0` -I./traceevent

OBJS := sysmon.o trace.o proc.o report.o summary.o traceevent/event-parse.o traceevent/parse-utils.c traceevent/trace-seq.o 

all: sysmon

sysmon:	$(OBJS)
	gcc $(OBJS) $(CFLAGS) -o $@

$(OBJS): sysmon.h

clean:
	rm -rf ../bin *.o sysmon
	
