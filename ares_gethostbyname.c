/* Copyright 1998 by the Massachusetts Institute of Technology.
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright
 * notice and this permission notice appear in supporting
 * documentation, and that the name of M.I.T. not be used in
 * advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 */

static const char rcsid[] = "$Id: ares_gethostbyname.c,v 1.2 1998-08-28 21:20:18 ghudson Exp $";

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include "ares.h"
#include "ares_private.h"

struct host_query {
  /* Arguments passed to ares_gethostbyname() */
  ares_channel channel;
  char *name;
  ares_host_callback callback;
  void *arg;

  const char *remaining_lookups;
};

static void next_lookup(struct host_query *hquery);
static void host_callback(void *arg, int status, unsigned char *abuf,
			  int alen);
static void end_hquery(struct host_query *hquery, int status,
		       struct hostent *host);
static int fake_hostent(const char *name, ares_host_callback callback,
			void *arg);
static int file_lookup(const char *name, struct hostent **host);

void ares_gethostbyname(ares_channel channel, const char *name, int family,
			ares_host_callback callback, void *arg)
{
  struct host_query *hquery;

  /* Right now we only know how to look up IPV4 and IPV6 addresses. */
  if (family != AF_INET && family != AF_INET6)
    {
      callback(arg, ARES_ENOTIMP, NULL);
      return;
    }

  if (fake_hostent(name, family, callback, arg))
    return;

  /* Allocate and fill in the host query structure. */
  hquery = malloc(sizeof(struct host_query));
  if (!hquery)
    {
      callback(arg, ARES_ENOMEM, NULL);
      return;
    }
  hquery->channel = channel;
  hquery->name = strdup(name);
  if (!hquery->name)
    {
      free(hquery);
      callback(arg, ARES_ENOMEM, NULL);
      return;
    }
  hquery->callback = callback;
  hquery->arg = arg;
  hquery->remaining_lookups = channel->lookups;

  /* Start performing lookups according to channel->lookups. */
  next_lookup(hquery);
}

static void next_lookup(struct host_query *hquery)
{
  int status;
  const char *p;
  struct hostent *host;

  for (p = hquery->remaining_lookups; *p; p++)
    {
      switch (*p)
	{
	case 'b':
	  /* DNS lookup */
	  hquery->remaining_lookups = p + 1;
	  ares_search(hquery->channel, hquery->name, C_IN, T_A, host_callback,
		      hquery);
	  return;

	case 'f':
	  /* Host file lookup */
	  status = file_lookup(hquery->name, &host);
	  if (status != ARES_ENOTFOUND)
	    {
	      end_hquery(hquery, status, host);
	      return;
	    }
	  break;
	}
    }
  end_hquery(hquery, ARES_ENOTFOUND, NULL);
}

static void host_callback(void *arg, int status, unsigned char *abuf, int alen)
{
  struct host_query *hquery = (struct host_query *) arg;
  struct hostent *host;

  if (status == ARES_SUCCESS)
    {
      status = ares_parse_a_reply(abuf, alen, &host);
      end_hquery(hquery, status, host);
    }
  else if (status == ARES_EDESTRUCTION)
    end_hquery(hquery, status, NULL);
  else
    next_lookup(hquery);
}

static void end_hquery(struct host_query *hquery, int status,
		       struct hostent *host)
{
  hquery->callback(hquery->arg, status, host);
  if (host)
    ares_free_hostent(host);
  free(hquery->name);
  free(hquery);
}

/* If the name looks like an IP address, fake up a host entry, end the
 * query immediately, and return true.  Otherwise return false.
 */
static int fake_hostent(const char *name, ares_host_callback callback,
			void *arg)
{
  struct in_addr addr;
  struct hostent hostent;
  const char *p;
  char *aliases[1] = { NULL };
  char *addrs[2] = { (char *) &addr, NULL };

  /* It only looks like an IP address if it's all numbers and dots. */
  for (p = name; *p; p++)
    {
      if (!isdigit(*p) && *p != '.')
	return 0;
    }

  /* It also only looks like an IP address if it's non-zero-length and
   * doesn't end with a dot.
   */
  if (p == name || *(p - 1) == '.')
    return 0;

  /* It looks like an IP address.  Figure out what IP address it is. */
  addr.s_addr = inet_addr(name);
  if (addr.s_addr == INADDR_NONE)
    {
      callback(arg, ARES_EBADNAME, NULL);
      return 1;
    }

  /* Duplicate the name, to avoid a constness violation. */
  hostent.h_name = strdup(name);
  if (!hostent.h_name)
    {
      callback(arg, ARES_ENOMEM, NULL);
      return 1;
    }

  /* Fill in the rest of the host structure and terminate the query. */
  hostent.h_aliases = aliases;
  hostent.h_addrtype = AF_INET;
  hostent.h_length = sizeof(struct in_addr);
  hostent.h_addr_list = addrs;
  callback(arg, ARES_SUCCESS, &hostent);

  free(hostent.h_name);
  return 1;
}

static int file_lookup(const char *name, struct hostent **host)
{
  FILE *fp;
  char **alias;
  int status;

  fp = fopen(PATH_HOSTS, "r");
  if (!fp)
    return ARES_ENOTFOUND;

  while ((status = ares__get_hostent(fp, host)) == ARES_SUCCESS)
    {
      if (strcasecmp((*host)->h_name, name) == 0)
	break;
      for (alias = (*host)->h_aliases; *alias; alias++)
	{
	  if (strcasecmp(*alias, name) == 0)
	    break;
	}
      if (*alias)
	break;
      ares_free_hostent(*host);
    }
  fclose(fp);
  if (status == ARES_EOF)
    status = ARES_ENOTFOUND;
  if (status != ARES_SUCCESS)
    *host = NULL;
  return status;
}
