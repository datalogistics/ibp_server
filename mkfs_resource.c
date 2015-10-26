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

#include "allocation.h"
#include "log.h"
#include "resource.h"
#include <stdio.h>
#include <assert.h>

//***********************************************************************************
//***********************************************************************************
//***********************************************************************************

static void _usage(FILE *f, int error) {
    fprintf(f, "mkfs.resource RID type device db_location [options]\n"
            "\t-b max_mbytes\n"
            "\t-d max_duration\n"
            "\t-h show help\n");
    fprintf(f, "\n");
    fprintf(f, "RID - Resource ID (integer)\n");
    fprintf(f, "type - Type of resource [dir|leveldb] (dir is default)\n");
    fprintf(f, "device - Device to be used for the resource.\n");
    fprintf(f, "db_location - Base directory to use for storing the DBes for the resource.\n");
    fprintf(f, "max_mbytes - Max number of MB to use. If missing it defaults to the entire disk.\n");
    fprintf(f, "max_duration - Maximum duration for allocation in seconds. If missing it defaults to 30 days.\n");
    fprintf(f, "\n");

    fflush(f);
    exit(error);
}

int main(int argc, const char **argv)
{
    int err = 0;
    ibp_off_t nbytes = 0;
    int max_duration = 0;

    apr_initialize();
    open_log("stderr");
   
    int opt = 0;
    while ((opt = getopt(argc, argv, "b:d:h?")) != -1) {
      switch (opt) {
        case 'b':
          nbytes = 1024 * 1024 * atoll(optarg);
          break;
        case 'd':
          max_duration = atoi(optarg);
          break;
        case 'h':
          _usage(stdout, EXIT_SUCCESS);
        case '?':
        default:
          _usage(stderr, EXIT_FAILURE);
      }
    }
    
    argc -= optind;
    argv += optind;
 
    if (argc == 0 || argc < 4) {
      fprintf(stderr, "\n Missing parameters\n");
      _usage(stderr, EXIT_FAILURE);
    }

    if (max_duration == 0)
      max_duration = 2592000;

    assert(apr_initialize() == APR_SUCCESS);
   
    rid_t rid;
    if (ibp_str2rid((char *)argv[0], &rid) != 0) {
      printf("Invalid RID format!  RID=%s\n", argv[0]);
    } else {
      // TODO: leveldb should have its own options eventually
      err = mkfs_resource(rid, (char *)argv[1], (char *)argv[2], (char *)argv[3], nbytes, max_duration);
    }
    apr_terminate();

    return(err);
}
