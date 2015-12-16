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
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <errno.h>
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
// setup_log_permissions - Make sure the log files have the correct ownership
//*****************************************************************************
int setup_log_permissions(char *lfile, Config_t *cfg) {
  int fd, rc;
  uid_t uid;
  gid_t gid;
  struct group *gr;
  struct passwd *pw;

  pw = getpwnam(cfg->server.user);
  if (pw) {
    uid = pw->pw_uid;
  }
  else {
    fprintf(stderr, "Unknown user '%s'\n", cfg->server.user);
    goto exit;
  }
  
  gr = getgrnam(cfg->server.group);
  if (gr) {
    gid = gr->gr_gid;
  }
  else {
    fprintf(stderr, "Unknown group '%s'\n", cfg->server.group);
    goto exit;
  }
  
  fd = open(lfile, O_WRONLY | O_CREAT, DEFFILEMODE);
  if (fd < 0) {
    fprintf(stderr, "Could not open file %s: %s!\n", lfile, strerror(errno));
    goto exit;
  }
  
  rc = fchown(fd, uid, gid);
  if (rc) {
    fprintf(stderr, "Could not change ownership on %s: %s\n", lfile, strerror(errno));
    goto exit_close;
  }
  
  close(fd);
  return 0;

 exit_close:
  close(fd);
 exit:
  exit(-1);
}

//*****************************************************************************
// daemonize - Make the ibp server run as a daemon
//*****************************************************************************
int ibp_daemonize(char *pid_file, char *user, char *group) {
  uid_t uid;
  gid_t gid;
  struct group *gr;
  struct passwd *pw;
  
  pid_t pid, sid, parent;
  
  /* already a daemon */
  if (getppid() == 1) return 0;
  
  /* Fork off the parent process */
  pid = fork();
  if (pid < 0) {
    exit(EXIT_FAILURE);
  }
  
  /* If we got a good PID, then we can exit the parent process. */
  if (pid > 0) {
    exit(EXIT_SUCCESS);
  }
  
  /* At this point we are executing as the child process */
  parent = getppid();
  pid = getpid();
  
  /* Change the file mode mask */
  umask(0);
  
  /* Create a new SID for the child process */
  sid = setsid();
  if (sid < 0) {
    exit(EXIT_FAILURE);
  }
  
  /* Cancel certain signals */
  /* These all may get overridden after daemonize */
  signal(SIGCHLD,SIG_DFL); /* A child process dies */
  signal(SIGTSTP,SIG_IGN); /* Various TTY signals */
  signal(SIGTTOU,SIG_IGN);
  signal(SIGTTIN,SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGTERM,SIG_DFL); /* Die on SIGTERM */
  
  if (pid) {
    FILE *pid_out = fopen(pid_file, "w+");
    if (!pid_out) {
      fprintf(stderr, "Couldn't open pid file: %s\n", pid_file);
      exit(-1);
    }
    
    fprintf(pid_out, "%d", getpid());
    fclose(pid_out);
  }
  
  if (group) {
    gr = getgrnam(group);
    if (gr) {
      gid = gr->gr_gid;
    }
    else {
      fprintf(stderr, "Unknown group '%s'\n", group);
      exit(EXIT_FAILURE);
    }
    
    if (setgid(gid) < 0) {
      fprintf(stderr, "Couldn't change process group to %s", group);
    }
  }
  
  if (user) {
    pw = getpwnam(user);
    if (pw) {
      uid = pw->pw_uid;
    }
    else {
      fprintf(stderr, "Unknown user '%s'\n", user);
      exit(EXIT_FAILURE);
    }
  }
  
  if (setuid(uid) < 0) {
    fprintf(stderr, "Couldn't change process user to %s", user);
  }
  
  kill(parent, SIGUSR1);
  
  return 0;
}

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
// resource_health_check - Does periodic health checks on the RIDs
//*****************************************************************************

void *resource_health_check(apr_thread_t *th, void *data) {
  Resource_t *r;
  resource_list_iterator_t it;
  apr_time_t next_check;
  ibp_task_t task;
  apr_time_t dt, dt_wait;
  Cmd_internal_mount_t *cmd;
  resource_usage_file_t usage;
  Stack_t *eject;
  FILE *fd;
  char *rname, *rid_name, *data_dir, *data_device;
  int i, j;
  pid_t pid;
  int err;
//int junk = 0;

  eject = new_stack();

  memset(&task, 0, sizeof(task));
  cmd = &(task.cmd.cargs.mount);
  dt_wait = apr_time_from_sec(global_config->server.rid_check_interval);
  next_check = apr_time_now() + dt_wait;
  dt = apr_time_from_sec(global_config->server.eject_timeout);

  apr_thread_mutex_lock(shutdown_lock);
  while (shutdown_now == 0) {
    if (apr_time_now() > next_check) {
       log_printf(5, "Running RID check\n");
       it = resource_list_iterator(global_config->rl);
//junk++;
       j = 0;
       while ((r = resource_list_iterator_next(global_config->rl, &it)) != NULL) {
          err = read_usage_file(r, &usage);
//if ((junk > 1) && (it == 1)) { err= 1; log_printf(0,"Forcing a failure\n"); }
          if (err == 0) {
             r->last_good_check = apr_time_now();  //** this should be done in resource.c But I'm the only one that ever touches the routine
          } else if (apr_time_now() > (r->last_good_check + dt)) {
             strncpy(cmd->crid, global_config->rl->res[r->rl_index].crid, sizeof(cmd->crid));
             strncpy(cmd->msg, "Health check failed. Ejecting drive.", sizeof(cmd->msg));

             //** Push the failed drive on the ejected stack
             j++;
             push(eject, strdup(r->data_pdev));
             push(eject, strdup(r->device));
             push(eject, strdup(cmd->crid));

             apr_thread_mutex_unlock(shutdown_lock);
             cmd->delay = 10;
             handle_internal_umount(&task);
             apr_thread_mutex_lock(shutdown_lock);
          }
       }
       resource_list_iterator_destroy(global_config->rl, &it);

       log_printf(5, "Finished RID check stack_size(eject)=%d\n", stack_size(eject));

       if ((j > 0) && (global_config->server.rid_eject_script != NULL)) {  //** Ejected something so run the eject program
          //** Make the RID list file and name
          i = strlen(global_config->server.rid_eject_tmp_path) + 1 + 6 + 30;
          assert((rname = malloc(i)) != NULL);
          snprintf(rname, i, "%s/eject." TT, global_config->server.rid_eject_tmp_path, apr_time_now());
          fd = fopen(rname, "w");
          if (fd == NULL) {
             log_printf(0, "ERROR: failed to create RID eject temp file: %s\n", rname);
             goto bail;
          }

          //** Line format: total # of RIDs | Good RIDs | Ejected/Bad RIDs
          i = j+resource_list_n_used(global_config->rl);
          fprintf(fd, "%d|%d|%d\n", i, resource_list_n_used(global_config->rl), j);

          //** Cycle though the good RIDs printing RID info
          //** Line format: RID|data_directory|data_device|status(0=good|1=bad)
          it = resource_list_iterator(global_config->rl);
          while ((r = resource_list_iterator_next(global_config->rl, &it)) != NULL) {
              fprintf(fd, "%s|%s|%s|%d\n", global_config->rl->res[r->rl_index].crid, r->device, r->data_pdev, 0);
          }
          resource_list_iterator_destroy(global_config->rl, &it);

          //** Now do the same for the ejected drives
         for (i=0; i<j; i++) {
             rid_name = pop(eject);  data_dir = pop(eject);  data_device = pop(eject);
             fprintf(fd, "%s|%s|%s|%d\n", rid_name, data_dir, data_device, 1);
             free(rid_name); free(data_dir); free(data_device);
          }
          fclose(fd);

          //** Now spawn the child process to do it's magic
          pid = fork();
          if (pid == 0) { //** Child process
             execl(global_config->server.rid_eject_script, global_config->server.rid_eject_script, rname, NULL);
             exit(0);  //** Should never get here
          } else if (pid == -1) { //** Fork error
            log_printf(0, "FORK error!!!! rname=%s\n", rname);
          }
       bail:
          free(rname);
       }

       next_check = apr_time_now() + apr_time_from_sec(global_config->server.rid_check_interval);
    }

    apr_thread_cond_timedwait(shutdown_cond, shutdown_lock, dt_wait);
  }
  apr_thread_mutex_unlock(shutdown_lock);
  
  free_stack(eject, 1);

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
  char statsd_postfix_default[1024];
  apr_time_t t;
  pMount_t *pm, *pmarray;

  // *** Initialize the data structure to default values ***
  server = &(cfg->server);
  server->user = "ibp";
  server->group = "ibp";
  server->pidfile = "/var/run/ibp_server.pid";
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
  server->rid_check_interval = 15;
  server->eject_timeout = 35;
  server->rid_log = "/log/rid.log";
  server->rid_eject_script = NULL;
  server->rid_eject_tmp_path = "/tmp";
  server->statsd_host = NULL;
  server->statsd_port = 8125;
  server->statsd_prefix = "ibp_server";
  gethostname(statsd_postfix_default, sizeof(statsd_postfix_default));
  for (i = 0; i < strlen(statsd_postfix_default); ++i) {
      if (statsd_postfix_default[i] == '.') {
          statsd_postfix_default[i] = '_';
      }
  }
  server->statsd_postfix = statsd_postfix_default;
  server->stats = NULL;

  cfg->dbenv_loc = "/tmp/ibp_dbenv";
  cfg->db_mem = 256;
  cfg->force_resource_rebuild = force_rebuild;
  cfg->truncate_expiration = 0;
  cfg->soft_fail = -1;

  // *** Parse the Server settings ***
  server->user = inip_get_string(keyfile, "server", "user", server->user);
  server->group = inip_get_string(keyfile, "server", "group", server->group);
  server->pidfile = inip_get_string(keyfile, "server", "pidfile", server->pidfile);
  server->port = inip_get_integer(keyfile, "server", "port", server->port);

  //** Make the default interface
  gethostname(iface_default, sizeof(iface_default));
  i = strlen(iface_default);
  append_printf(iface_default, &i, sizeof(iface_default), ":%d", server->port);

  char *iface_str = inip_get_string(keyfile, "server", "interfaces", iface_default);

  char *sub_iface_str = inip_get_string(keyfile, "server", "substitute_map", NULL);
  char *sub_ip_list[100];
  i = 0; k = 0; bstate = NULL;
  if (sub_iface_str != NULL) {
    //** sub_iface_str format: <interface_ip1>:<substitute_ip1>;<interface_ip2>:<substitute_ip2>
    sub_ip_list[i] = string_token(sub_iface_str, ";", &bstate, &k);
    while (strcmp(sub_ip_list[i], "") != 0) {
       i++;
       sub_ip_list[i] = string_token(NULL, ";", &bstate, &k);
    }
  }
  unsigned int num_sub_ip_list = i;

  //** Determine the number of interfaces
  char *list[100];
  i = 0; k = 0; bstate = NULL;
  list[i] = string_token(iface_str, ";", &bstate, &k);
  while (strcmp(list[i], "") != 0) {
     i++;
     list[i] = string_token(NULL, ";", &bstate, &k);
  }

  server->n_iface = i;

  //** Now parse and store them
  server->iface = (interface_t *)malloc(sizeof(interface_t)*server->n_iface);
  interface_t *iface;
  int j = 0;
  i = 0; k = 0; bstate = NULL;
  for (i=0; i<server->n_iface; i++) {
      iface = &(server->iface[i]);
      iface->hostname = strdup(string_token(list[i], ":", &bstate, &k));
      if (sscanf(string_token(NULL, " ", &bstate, &k), "%d", &(iface->port)) != 1) {
         iface->port = server->port;
      }
      iface->sub_hostname = NULL;
      for (j=0; j<num_sub_ip_list; ++j) {
         if(strstr(sub_ip_list[j], iface->hostname) != NULL) {
            //** sub_iface_str format: <interface_ip1>:<substitute_ip1>
            int size_to_adv = strlen(iface->hostname) + 1;
            //** we need to find <substitute_ip1>
            iface->sub_hostname = strdup(sub_ip_list[j] + size_to_adv);
         }
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

  server->rid_check_interval = inip_get_integer(keyfile, "server", "rid_check_interval", server->rid_check_interval);
  server->eject_timeout = inip_get_integer(keyfile, "server", "eject_timeout", server->eject_timeout);
  server->rid_log = inip_get_string(keyfile, "server", "rid_log", server->rid_log);
  server->rid_eject_script = inip_get_string(keyfile, "server", "rid_eject_script", server->rid_eject_script);
  server->rid_eject_tmp_path = inip_get_string(keyfile, "server", "rid_eject_tmp_path", server->rid_eject_tmp_path);

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
  server->statsd_host = inip_get_string(keyfile, "server", "statsd_host", server->statsd_host);
  server->statsd_port = inip_get_integer(keyfile, "server", "statsd_port", server->statsd_port);
  server->statsd_prefix = inip_get_string(keyfile, "server", "statsd_prefix", server->statsd_prefix);
  server->statsd_postfix = inip_get_string(keyfile, "server", "statsd_postfix", server->statsd_postfix);
  if (server->statsd_host) {
    server->stats = statsd_init_with_namespace(server->statsd_host, server->statsd_port, 
                                                server->statsd_prefix, server->statsd_postfix);
  } else {
    server->stats = NULL;
  }

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

  if (server->rid_eject_script) free(server->rid_eject_script);
  if (server->rid_eject_tmp_path) free(server->rid_eject_tmp_path);
  free(server->password);
  free(server->logfile);
  free(server->default_acl);
  free(cfg->dbenv_loc);
  free(server->rid_log);

  for (i=0; i<server->n_iface; i++) {
    free(server->iface[i].hostname);
    free(server->iface[i].sub_hostname);
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
  apr_thread_cond_broadcast(shutdown_cond);
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
  if (cfg->server.stats) {
     statsd_finalize(cfg->server.stats);
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
  apr_thread_t *rid_check_thread;
  apr_status_t dummy;

  assert(apr_initialize() == APR_SUCCESS);
  assert(apr_pool_create(&global_pool, NULL) == APR_SUCCESS);

  init_random();  // Make sure and initialize the random number generator;

  shutdown_now = 0;

  global_config = &config;   //** Make the global point to what's loaded
  memset(global_config, 0, sizeof(Config_t));  //** init the data
  global_network = NULL;

  if (argc < 2) {
     printf("ibp_server [-d] [-r] config_file\n\n");
     printf("-r          - Rebuild RID databases. Same as force_rebuild=2 in config file\n");
     printf("-d          - Run as a daemon\n");
     printf("config_file - Configuration file\n");
     return(0);
  }

  int daemon = 0;
  int force_rebuild = 0;
  int argcount = 1;
  for (i=1; i<argc; i++) {
     if (strcmp(argv[i], "-d") == 0) {
        daemon = 1;
	argcount++;
     } else if (strcmp(argv[i], "-r") == 0) {
        force_rebuild = 2;
	argcount++;
     }
  }

  if (argcount < argc) {
      config_file = (char *)argv[argc-1];
      global_config->config_file = config_file;
  }
  else {
      log_printf(0, "ibp_server: No config file given!\n");
      return(-1);
  }

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

  //** Setup log file permissions on the system
  setup_log_permissions(config.server.logfile, &config);
  setup_log_permissions(config.server.alog_name, &config);

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
  apr_thread_cond_create(&shutdown_cond, global_pool);

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
      } else {
	  ibp_daemonize(config.server.pidfile,
			config.server.user,
			config.server.group);
	  log_printf(0, "Running as a daemon.\n");
	  flush_log();
	  fclose(stdin);     //** Need to close all the std* devices **
	  fclose(stdout);
	  fclose(stderr);
	  
	  /*** Not sure why this is even here, should ignore stdout/stderr in daemon mode
	  char fname[1024];
	  fname[1023] = '\0';
	  snprintf(fname, 1023, "%s.stdout", config.server.logfile);
	  assert((stdout = fopen(fname, "w")) != NULL);
	  snprintf(fname, 1023, "%s.stderr", config.server.logfile);
	  assert((stderr = fopen(fname, "w")) != NULL);
	  */
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

  //** Launch the RID health checker thread
  apr_thread_create(&rid_check_thread, NULL, resource_health_check, NULL, global_pool);

  //*** Start the activity log ***
  alog_open();

  start_unis_registration();

  server_loop(&config);     //***** Main processing loop ******

  //** Wait forthe healther checker thread to complete
  apr_thread_join(&dummy, rid_check_thread);

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
