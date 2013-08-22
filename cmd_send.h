#ifndef _CMD_SEND_H_
#define _CMD_SEND_H_

#include "network.h"

#ifdef __cplusplus
extern "C" {
#endif

NetStream_t *cmd_send(char *host, int port, char *cmd, char **res_buffer, int timeout);

#ifdef __cplusplus
}
#endif


#endif

