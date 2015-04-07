#ifndef _H_STATSD_CLIENT
#define _H_STATSD_CLIENT
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define STATSD_COUNT(link, name, count) statsd_count(link, name, count, 1.0)
#define STATSD_TIMER_START(variable) time_t variable; time(& variable )
#define STATSD_TIMER_END(link, name, variable) time_t variable ## _end; time(& variable ## _end); statsd_timing(link, name, (int) (difftime(variable ## _end, variable) * 1000.0))
#define STATSD_TIMER_RESET(variable) time(& variable)


struct _statsd_link  {
	struct sockaddr_in server;
	int sock;
	char *ns;
    char *postfix;
};

typedef struct _statsd_link statsd_link;


statsd_link *statsd_init(const char *host, int port);
statsd_link *statsd_init_with_namespace(const char *host, int port, const char *ns, const char *postfix);
void statsd_finalize(statsd_link *link);

/*
  write the stat line to the provided buffer,
  type can be "c", "g" or "ms"
  lf - whether line feed needs to be added
 */
void statsd_prepare(statsd_link *link, char *stat, size_t value, const char *type, float sample_rate, char *buf, size_t buflen, int lf);

/* manually send a message, which might be composed of several lines. Must be null-terminated */
int statsd_send(statsd_link *link, const char *message);

int statsd_inc(statsd_link *link, char *stat, float sample_rate);
int statsd_dec(statsd_link *link, char *stat, float sample_rate);
int statsd_count(statsd_link *link, char *stat, size_t count, float sample_rate);
int statsd_gauge(statsd_link *link, char *stat, size_t value);
int statsd_timing(statsd_link *link, char *stat, size_t ms);
#endif
