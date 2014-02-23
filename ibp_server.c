/*
Advanced Computing Center for Research and Education Proprietary License
Version 1.0 (April 2006)

Copyright (c) 2006, Advanced Computing Center for Research and Education,
 Vanderbilt University, All rights reserved.

This Work is the sole and exclusive property of the Advanced Computing Center
for Research and Education department at Vanderbilt University.  No right to
disclose or otherwise disseminate any of the information contained herein is
granted by virtue of your possession of this software except in accordance with
the terms and conditions of a separate License Agreement entered into with
Vanderbilt University.

THE AUTHOR OR COPYRIGHT HOLDERS PROVIDES THE "WORK" ON AN "AS IS" BASIS,
WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, TITLE, FITNESS FOR A PARTICULAR
PURPOSE, AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Vanderbilt University
Advanced Computing Center for Research and Education
230 Appleton Place
Nashville, TN 37203
http://www.accre.vanderbilt.edu
*/ 

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <apr_time.h>
#include <apr_signal.h>
#include <sys/types.h>
#include <unistd.h>
#include "ibp_server.h"
#include "debug.h"
#include "log.h"
#include "dns_cache.h"
#include "lock_alloc.h"
#include "activity_log.h"

//***** This is just used in the parallel mounting of the resources ****
typedef struct {
  apr_thread_t *thread_id;
  DB_env_t *dbenv;
  inip_file_t *keyfile;
  char *group;
  int force_resource_rebuild;
} pMount_t;

//*****************************************************************************
// parallel_mount_resource - Mounts a resource in a separate thread
//*****************************************************************************

void *parallel_mount_resource(apr_thread_t *th, void *data) {
   pMount_t *pm = (pMount_t *)data;
   Resource_t *r;

   assert((r = (Resource_t *)malloc(sizeof(Resource_t))) != NULL);

   int err = mount_resource(r, pm->keyfile, pm->group, pm->dbenv, 
        pm->force_resource_rebuild, global_config->server.lazy_allocate, 
        global_config->truncate_expiration);

   if (err != 0) {
     log_printf(0, "parallel_mount_resource:  Error mounting resource!!!!!\n");
     exit(-10);
   }

   free(pm->group);

   r->rl_index = resource_list_insert(global_config->rl, r);

   //** Launch the garbage collection threads
//   launch_resource_cleanup_thread(r);  *** Not safe to do this here due to fork() becing called after mount


   apr_thread_exit(th, 0);
   return(0);   //** Never gets here but suppresses compiler warnings
}

//*****************************************************************************
// log_preamble - Print the initial log file output
//*****************************************************************************

void log_preamble(Config_t *cfg)
{
  char buffer[100*1024];
  int used = 0;
  apr_time_t t = get_starttime();
  apr_ctime(buffer, t);

  log_printf(0, "\n");
  log_printf(0, "*****************************************************************\n");
  log_printf(0, "Starting ibp_server on %s\n", buffer);
  log_printf(0, "*****************************************************************\n");
  log_printf(0, "\n");

  log_printf(0, "*********************Printing configuration file **********************\n\n");


  print_config(buffer, &used, sizeof(buffer), cfg);
  fprintf(log_fd(), "%s", buffer);

  log_printf(0, "*****************************************************************\n\n");
}


//*****************************************************************************
//  parse_config - Parses the config file(fname) and initializes the config
//                 data structure (cfg).
//*****************************************************************************

int parse_config(inip_file_t *keyfile, Config_t *cfg, int force_rebuild)
{
  Server_t *server;
  char *str, *bstate;
  int val, k, i, timeout_ms;
  char iface_default[1024];
  apr_time_t t;
  pMount_t *pm, *pmarray;

  // *** Initialize the data structure to default values ***
  server = &(cfg->server);
  server->max_threads = 64;
  server->max_pending = 16;
  server->min_idle = apr_time_make(60, 0);
  server->stats_size = 5000;
  timeout_ms = 1 * 1000;   //** Wait 1 sec  
//  set_net_timeout(&(server->timeout), 1, 0);  //**Wait 1sec
  server->timeout_secs = timeout_ms / 1000;
  server->logfile = "ibp.log";
  server->log_overwrite = 0;
  server->log_level = 0;
  server->log_maxsize = 100;
  server->debug_level = 0;
  server->timestamp_interval = 60;
  server->password = DEFAULT_PASSWORD;
  server->lazy_allocate = 1;
  server->backoff_scale = 1.0/10;
  server->backoff_max = 30;
  server->big_alloc_enable = (sizeof(off_t) > 4) ? 1 : 0;  
  server->splice_enable = 0;
  server->alog_name = "ibp_activity.log";
  server->alog_max_size = 50;
  server->alog_max_history = 1;
  server->alog_host = NULL;
  server->alog_port = 0;
  server->port = IBP_PORT;
  server->return_cap_id = 1;
  cfg->dbenv_loc = "/tmp/ibp_dbenv";
  cfg->db_mem = 256;
  cfg->force_resource_rebuild = force_rebuild;
  cfg->truncate_expiration = 0;
  cfg->soft_fail = -1;

  // *** Parse the Server settings ***
  server->port = inip_get_integer(keyfile, "server", "port", server->port);

  //** Make the default interface
  gethostname(iface_default, sizeof(iface_default));
  i = strlen(iface_default);
  append_printf(iface_default, &i, sizeof(iface_default), ":%d", server->port);

  char *iface_str = inip_get_string(keyfile, "server", "interfaces", iface_default);

  //** Determine the number of interfaces
  char *list[100];
  i = 0;
  list[i] = string_token(iface_str, ";", &bstate, &k);
  while (strcmp(list[i], "") != 0) {
     i++;
     list[i] = string_token(NULL, ";", &bstate, &k);
  }

  server->n_iface = i;

  //** Now parse and store them
  server->iface = (interface_t *)malloc(sizeof(interface_t)*server->n_iface);
  interface_t *iface;
  for (i=0; i<server->n_iface; i++) {
      iface = &(server->iface[i]);
      iface->hostname = string_token(list[i], ":", &bstate, &k);
      if (sscanf(string_token(NULL, " ", &bstate, &k), "%d", &(iface->port)) != 1) {
         iface->port = server->port;
      }
  }

  server->max_threads = inip_get_integer(keyfile, "server", "threads", server->max_threads);
  server->max_pending = inip_get_integer(keyfile, "server", "max_pending", server->max_pending);
  t = 0; t = inip_get_integer(keyfile, "server", "min_idle", t);
  if (t != 0) server->min_idle = apr_time_make(t, 0);
  val = inip_get_integer(keyfile, "server", "max_network_wait_ms", timeout_ms);

  int sec = val/1000;
  int us = val - 1000*sec;
  us = us * 1000;  //** Convert from ms->us
  server->timeout_secs = sec;
//log_printf(0, "parse_config: val=%d sec=%d us=%d\n", val, sec, us);
  set_net_timeout(&(server->timeout), sec, us);  //**Convert it from ms->us

  server->stats_size =  inip_get_integer(keyfile, "server", "stats_size", server->stats_size);
  server->password = inip_get_string(keyfile, "server", "password", server->password);
  server->logfile = inip_get_string(keyfile, "server", "log_file", server->logfile);
  server->log_level = inip_get_integer(keyfile, "server", "log_level", server->log_level);
  server->log_maxsize = inip_get_integer(keyfile, "server", "log_maxsize", server->log_maxsize) * 1024 * 1024;
  server->debug_level = inip_get_integer(keyfile, "server", "debug_level", server->debug_level);
  server->lazy_allocate = inip_get_integer(keyfile, "server", "lazy_allocate", server->lazy_allocate);
  server->big_alloc_enable = inip_get_integer(keyfile, "server", "big_alloc_enable", server->big_alloc_enable);
  server->splice_enable = inip_get_integer(keyfile, "server", "splice_enable", server->splice_enable);
  server->backoff_scale = inip_get_double(keyfile, "server", "backoff_scale", server->backoff_scale);
  server->backoff_max = inip_get_double(keyfile, "server", "backoff_max", server->backoff_max);

  server->return_cap_id = inip_get_integer(keyfile, "server", "return_cap_id", server->return_cap_id);

  cfg->dbenv_loc = inip_get_string(keyfile, "server", "db_env_loc", cfg->dbenv_loc);
  cfg->db_mem = inip_get_integer(keyfile, "server", "db_mem", cfg->db_mem);

  server->alog_name = inip_get_string(keyfile, "server", "activity_file", server->alog_name);
  server->alog_max_size = inip_get_integer(keyfile, "server", "activity_maxsize", server->alog_max_size) * 1024 * 1024;
  server->alog_max_history = inip_get_integer(keyfile, "server", "activity_max_history", server->alog_max_history);
  server->alog_host = inip_get_string(keyfile, "server", "activity_host", server->alog_host);
  server->alog_port = inip_get_integer(keyfile, "server", "activity_port", server->alog_port);


  if (force_rebuild == 0) {  //** The command line option overrides the file
     cfg->force_resource_rebuild = inip_get_integer(keyfile, "server", "force_resource_rebuild", cfg->force_resource_rebuild);
  }
  cfg->truncate_expiration = inip_get_integer(keyfile, "server", "truncate_duration", cfg->truncate_expiration);

  i = inip_get_integer(keyfile, "server", "soft_fail", 0);
  cfg->soft_fail = (i==0) ? -1 : 0;

  //*** Do some initial config of the log and debugging info ***
  open_log(cfg->server.logfile);            
  set_log_level(cfg->server.log_level);
  set_debug_level(cfg->server.debug_level);
  set_log_maxsize(cfg->server.log_maxsize);

  // *** Now iterate through each resource which is assumed to be all groups beginning with "resource" ***      
  apr_pool_t *mount_pool;
  apr_pool_create(&mount_pool, NULL);
  cfg->dbenv = create_db_env(cfg->dbenv_loc, cfg->db_mem, cfg->force_resource_rebuild);
  k= inip_n_groups(keyfile);
  assert((pmarray = (pMount_t *)malloc(sizeof(pMount_t)*(k-1))) != NULL);
  inip_group_t *igrp = inip_first_group(keyfile);
  val = 0;
  for (i=0; i<k; i++) {
      str = inip_get_group(igrp);      
      if (strncmp("resource", str, 8) == 0) {
         pm = &(pmarray[val]);
         pm->keyfile = keyfile;
         pm->group = strdup(str);
         pm->dbenv = cfg->dbenv;
         pm->force_resource_rebuild = cfg->force_resource_rebuild;
  
         apr_thread_create(&(pm->thread_id), NULL, parallel_mount_resource, (void *)pm, mount_pool);

         val++;
      }

      igrp = inip_next_group(igrp);
  }  

  //** Wait for all the threads to join **
  apr_status_t dummy;
  for (i=0; i<val; i++) {
     apr_thread_join(&dummy, pmarray[i].thread_id);
  }

  free(pmarray);

  if (val < 0) {
     printf("parse_config:  No resources defined!!!!\n");
     abort();
  }

  return(0);
}

//*****************************************************************************
//*****************************************************************************

void cleanup_config(Config_t *cfg)
{
  Server_t *server;
  int i;

  server = &(cfg->server);

  free(server->password);
  free(server->logfile);
  free(server->default_acl);
  free(cfg->dbenv_loc);

  for (i=0; i<server->n_iface; i++) {
    free(server->iface[i].hostname);
  }
  free(server->iface);
}

//*****************************************************************************
//*****************************************************************************

void signal_shutdown(int sig)
{
  char date[128];
  apr_ctime(date, apr_time_now());

  log_printf(0, "Shutdown requested on %s\n", date);

  apr_thread_mutex_lock(shutdown_lock);
  shutdown_now = 1;
  apr_thread_mutex_unlock(shutdown_lock);

  signal_taskmgr();
  wakeup_network(global_network);

  return;
}

//*****************************************************************************
// ibp_shutdown - Shuts down everything
//*****************************************************************************

int ibp_shutdown(Config_t *cfg)
{
  int err;
  Resource_t *r;
  resource_list_iterator_t it;

  //** Close all the resources **
  it = resource_list_iterator(cfg->rl);
  while ((r = resource_list_iterator_next(cfg->rl, &it)) != NULL) {
    if ((err = umount_resource(r)) != 0) {
       char tmp[RID_LEN];
       log_printf(0, "ibp_server: Error closing Resource %s!  Err=%d\n",ibp_rid2str(r->rid, tmp), err);
    }
    free(r);
  }  
  resource_list_iterator_destroy(cfg->rl, &it);

  //** Now clsoe the DB environment **
  if ((err = close_db_env(cfg->dbenv)) != 0) {
     log_printf(0, "ibp_server: Error closing DB envirnment!  Err=%d\n", err);
  }

  return(0);
}

//*****************************************************************************
// configure_signals - Configures the signals
//*****************************************************************************

void configure_signals()
{

  //***Attach the signal handler for shutdown
  apr_signal_unblock(SIGQUIT);
  apr_signal(SIGQUIT, signal_shutdown);
//  if (signal(SIGQUIT, signal_shutdown) == SIG_ERR) {
//     log_printf(0, "Error installing shutdown signal handler!\n");
//  }     
//  if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
//     log_printf(0, "Error installing shutdown signal handler!\n");
//  }     

  //** Want everyone to ignore SIGPIPE messages
#ifdef SIGPIPE
  apr_signal_block(SIGPIPE);
#endif
}

//*****************************************************************************
//*****************************************************************************
//*****************************************************************************

int main(int argc, const char **argv)
{
  Config_t config;
  char *config_file;
  int i, j, k;

  assert(apr_initialize() == APR_SUCCESS);
  assert(apr_pool_create(&global_pool, NULL) == APR_SUCCESS);

  shutdown_now = 0;

  global_config = &config;   //** Make the global point to what's loaded
  memset(global_config, 0, sizeof(Config_t));  //** init the data
  global_network = NULL;

  if (argc < 1) {
     printf("ibp_server [-d] [-r] config_file\n\n");
     printf("-r          - Rebuild RID databases. Same as force_rebuild=2 in config file\n");
     printf("-d          - Run as a daemon\n");
     printf("config_file - Configuration file\n");
     return(0);
  }

  int daemon = 0;
  int force_rebuild = 0;
  for (i=1; i<argc; i++) {
     if (strcmp(argv[i], "-d") == 0) {
        daemon = 1;
     } else if (strcmp(argv[i], "-r") == 0) {
        force_rebuild = 2;
     }
  }

  config_file = (char *)argv[argc-1];
  global_config->config_file = config_file;

  //*** Open the config file *****
  printf("Config file: %s\n\n", config_file);

  inip_file_t *keyfile;

  //* Load the config file
  keyfile = inip_read(config_file);
  if (keyfile == NULL) {
    log_printf(0, "ibp_load_config:  Error parsing config file! file=%s\n", config_file);
    return(-1);
  }


  set_starttime();

  config.rl = create_resource_list(1);

  //** Parse the global options first ***
  parse_config(keyfile, &config, force_rebuild);

  //** Make sure we have enough fd's
  i = sysconf(_SC_OPEN_MAX);
  j = 3*config.server.max_threads + 2*resource_list_n_used(config.rl) + 64;
  if (i < j) {
     k = (i - 2*resource_list_n_used(config.rl) - 64) / 3;
      log_printf(0, "ibp_server: ERROR Too many threads!  Current threads=%d, n_resources=%d, and max fd=%d.\n", config.server.max_threads, resource_list_n_used(config.rl), i);
     log_printf(0, "ibp_server: Either make threads < %d or increase the max fd > %d (ulimit -n %d)\n", k, j, j);
     shutdown_now = 1;
  }

  init_thread_slots(2*config.server.max_threads);  //** Make pigeon holes

  dns_cache_init(1000);
  init_subnet_list(config.server.iface[0].hostname);

  //*** Install the commands: loads Vectable info and parses config options only ****
  install_commands(keyfile);

  //save unis configs
  parse_unis_config(keyfile);

  inip_destroy(keyfile);   //Free the keyfile context

  log_preamble(&config);

  configure_signals();   //** Setup the signal handlers

  //*** Set up the shutdown variables
  apr_thread_mutex_create(&shutdown_lock, APR_THREAD_MUTEX_DEFAULT, global_pool);

//  log_printf(0, "Looking up resource 2 and printing info.....\n")
//  print_resource(resource_lookup(config.rl, "2"), log_fd());

  init_stats(config.server.stats_size);
  lock_alloc_init();

  //***Launch as a daemon if needed***
  if (daemon == 1) {    //*** Launch as a daemon ***
     if ((strcmp(config.server.logfile, "stdout") == 0) || 
         (strcmp(config.server.logfile, "stderr") == 0)) {
        log_printf(0, "Can't launch as a daemom because log_file is either stdout or stderr\n");  
        log_printf(0, "Running in normal mode\n");  
     } else if (fork() == 0) {    //** This is the daemon
        log_printf(0, "Running as a daemon.\n");
        flush_log();
        fclose(stdin);     //** Need to close all the std* devices **
        fclose(stdout);
        fclose(stderr);

        char fname[1024];
        fname[1023] = '\0';
        snprintf(fname, 1023, "%s.stdout", config.server.logfile);
        assert((stdout = fopen(fname, "w")) != NULL);
        snprintf(fname, 1023, "%s.stderr", config.server.logfile);
        assert((stderr = fopen(fname, "w")) != NULL);
//        stdout = stderr = log_fd();  //** and reassign them to the log device         
printf("ibp_server.c: STDOUT=STDERR=LOG_FD() dnoes not work!!!!!!!!!!!!!!!!!!!!!!!!\n");
     } else {           //** Parent exits
        exit(0);         
     }    
  }

//  test_alloc();   //** Used for testing allocation speed only

  //*** Initialize all command data structures.  This is mainly 3rd party commands ***
  initialize_commands();


  //** Launch the garbage collection threads ...AFTER fork!!!!!!
  resource_list_iterator_t it;
  Resource_t *r;
  it = resource_list_iterator(global_config->rl);
  while ((r = resource_list_iterator_next(global_config->rl, &it)) != NULL) {
     launch_resource_cleanup_thread(r);
  }
  resource_list_iterator_destroy(global_config->rl, &it);

  //*** Start the activity log ***
  alog_open();

  start_unis_registration();

  server_loop(&config);     //***** Main processing loop ******

  //*** Shutdown the activity log ***
  alog_close();

  //*** Destroy all the 3rd party structures ***
  destroy_commands();

  lock_alloc_destroy();

  destroy_thread_slots();

  ibp_shutdown(&config);

  free_resource_list(config.rl);

  free_stats();

  cleanup_config(&config);
  log_printf(0, "main: Completed shutdown. Exiting\n");
//  close_log();
//  close_debug();

  apr_terminate();

  return(0);
}
