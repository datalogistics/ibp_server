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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "rid.h"
#include "log.h"

//*****************************************************************

char *ibp_rid2str(rid_t rid, char *buffer)
{
  strncpy(buffer, rid.name, RID_LEN);

  return(buffer);
}

//*****************************************************************

int ibp_str2rid(char *rid_str, rid_t *rid)
{
  strncpy(rid->name, rid_str, RID_LEN);

  return(0);
}

//*****************************************************************

void ibp_empty_rid(rid_t *rid)
{
  sprintf(rid->name, "0");
}

//*****************************************************************

int ibp_rid_is_empty(rid_t rid)
{
  if (strcmp(rid.name, "0") == 0) {
     return(1);
  }

  return(0);
}

//*****************************************************************

int ibp_compare_rid(rid_t rid1, rid_t rid2)
{
  return(strncmp(rid1.name, rid2.name, RID_LEN));
}




