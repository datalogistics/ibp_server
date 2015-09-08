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
  unis_loc location;
  char* unis_name = inip_get_string(kf, "unis", "name", NULL);
  char* unis_type = inip_get_string(kf, "unis", "type", NULL);
  char* unis_endpoint = inip_get_string(kf, "unis", "endpoint", NULL);
  char* unis_proto_name = inip_get_string(kf, "unis", "protocol_name", "ibp");
  //Todo: Do we need to support more than one ips here?
  char* unis_publicip = inip_get_string(kf, "unis", "publicip", NULL);
  int unis_publicport = inip_get_integer(kf, "unis", "publicport", -1);
  int unis_do_register = 1;
  int unis_reg_interval = inip_get_integer(kf, "unis", "registration_interval", UNIS_REG_INTERVAL);
  char* client_cert_path = inip_get_string(kf, "unis", "client_certfile", NULL);
  char* client_key_path = inip_get_string(kf, "unis", "client_keyfile", NULL);
  int use_ssl = inip_get_integer(kf, "unis", "use_ssl", 0);

  location.country = inip_get_string(kf, "unis", "country", NULL);
  location.street_address = inip_get_string(kf, "unis", "street", NULL);
  location.state = inip_get_string(kf, "unis", "state", NULL);
  location.institution = inip_get_string(kf, "unis", "institution", NULL);
  location.zipcode = inip_get_string(kf, "unis", "zipcode", NULL);
  location.email = inip_get_string(kf, "unis", "email", NULL);
  location.lat = inip_get_double(kf, "unis", "latitude", 0);
  location.lon = inip_get_double(kf, "unis", "longitude", 0);

  if(!unis_name || !unis_type || !unis_endpoint) {
    log_printf(0, "register_unis: no unis information present. Unis registration will not be done.");
    return;
  }

  config = malloc(sizeof(unis_config));
  config->name = unis_name;
  config->type = unis_type;
  config->endpoint = unis_endpoint;
  config->protocol_name = unis_proto_name;
  config->iface = unis_publicip;
  config->port = unis_publicport;
  config->do_register = unis_do_register;
  config->registration_interval = unis_reg_interval;
  config->refresh_timer = UNIS_REFRESH_TO;
  //ssl params
  config->certfile = client_cert_path;
  config->keyfile = client_key_path;
  config->use_ssl = use_ssl;
  config->keypass  = NULL;
  config->cacerts = NULL;
  memcpy(&config->loc_info, &location, sizeof(location));

  log_printf(5, "UNIS: %s:%s:%s:%s:%s:%d:%d:%d:%d:%s:%s:%d", config->name,
	     config->type, config->endpoint, config->protocol_name,
	     config->iface, config->port, config->do_register,
	     config->registration_interval, config->refresh_timer,
	     config->certfile, config->keyfile, config->use_ssl);
}

//*************************************************************************
//  _print_log - internal function to be passed to library to catch logs
//*************************************************************************
void _print_log(int level, const char* msg) {
    log_printf(level, msg);
}

//  start_unis_registration - initializes the unis_registration api
//*************************************************************************
void start_unis_registration(){
  register_log_callback_libunis_c(_print_log);
  if(config != NULL) {
    if(unis_init(config) == 0) {
      log_printf(5, "register_unis: unis registration is successful.");
    } else {
      log_printf(0, "register_unis: error in unis registration.");
    }
  }
}

#else

//dummy definitions
void start_unis_registration(){}
void parse_unis_config(inip_file_t *kf){}

#endif //_ENABLE_UNIS_C
