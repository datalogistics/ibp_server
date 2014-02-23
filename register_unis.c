#include "ibp_server.h"

#ifdef _ENABLE_UNIS_C
#include <unis_registration.h>
// to store configurations
static unis_config* config = NULL;

//*************************************************************************
//  parse_unis_config - parses the config and stores for later
//*************************************************************************
void parse_unis_config(inip_file_t *kf)
{
  char* unis_name = inip_get_string(kf, "unis", "name", NULL);
  char* unis_type = inip_get_string(kf, "unis", "type", NULL);
  char* unis_endpoint = inip_get_string(kf, "unis", "endpoint", NULL);
  //Todo: Do we need to support more than one ips here?
  char* unis_publicip = inip_get_string(kf, "unis", "publicip", NULL);
  //Todo: Do we need to obtain interfaces?
  int unis_publicport = inip_get_integer(kf, "unis", "publicport", -1);
  int unis_do_register = inip_get_integer(kf, "unis", "init_register", 0);
  int unis_reg_interval = inip_get_integer(kf, "unis", "registration_interval", UNIS_REG_INTERVAL);

  if(!unis_name || !unis_type || !unis_endpoint) {
    log_printf(0, "register_unis: no unis information present. Unis registration will not be done.");
    return;
  }

  unis_ip_port *ip_port = malloc(sizeof(unis_ip_port));
  ip_port->ip = strdup(unis_publicip);
  ip_port->port = unis_publicport;

  config = malloc(sizeof(unis_config));
  config->name = unis_name;
  config->type = unis_type;
  config->endpoint = unis_endpoint;
  config->ifaces.ip_ports = ip_port;
  config->ifaces.count = 1;
  config->do_register = unis_do_register;
  config->registration_interval = unis_reg_interval;
  config->refresh_timer = UNIS_REFRESH_TO;

  log_printf(5, "UNIS: %s:%s:%s%s:%d:%d:%d:%d", config->name, config->type, config->endpoint, config->ifaces.ip_ports[0].ip, config->ifaces.count, config->do_register, config->registration_interval, config->refresh_timer);
}

//*************************************************************************
//  start_unis_registration - initializes the unis_registration api
//*************************************************************************
void start_unis_registration(){
  if(config != NULL) {
    if(unis_init(config) == 0) {
      log_printf(5, "register_unis: unis registration is successful.");
    } else {
      log_printf(5, "register_unis: error in unis registration.");
    }
  }
}

#else

//dummy definitions
void start_unis_registration(){}
void parse_unis_config(inip_file_t *kf){}

#endif //_ENABLE_UNIS_C
