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

static const char rcsid[] = "$Id: ares_gethostbyname.c,v 1.1 1998-08-13 18:06:30 ghudson Exp $";

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
static int fake_hostent(const char *name, struct hostent **host);
static int file_lookup(const char *name, struct hostent **host);

void ares_gethostbyname(ares_channel channel, const char *name, int family,
			ares_host_callback callback, void *arg)
{
  const char *p;
  int status;
  struct hostent *host;
  struct host_query *hquery;

  /* Right now we only know how to look up Internet addresses. */
  if (family != AF_INET)
    {
      callback(arg, ARES_ENOTIMP, NULL);
      return;
    }

  /* If the name looks like an IP address, fake up a host entry and
   * end the query immediately.
   */
  for (p = name; *p; p++)
    {
      if (!isdigit(*p) && *p != '.')
	break;
    }
  if (!*p)
    {
      status = fake_hostent(name, &host);
      callback(arg, status, host);
      if (host)
	ares_free_hostent(host);
      return;
    }

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

static int fake_hostent(const char *name, struct hostent **host)
{
  struct in_addr addr;
  struct hostent *hostent;

  *host = NULL;

  addr.s_addr = inet_addr(name);
  if (addr.s_addr == INADDR_NONE)
    return ARES_EBADNAME;

  /* Allocate five bits of memory for the host structure.  Yuck. */
  hostent = malloc(sizeof(struct hostent));
  if (hostent)
    {
      hostent->h_name = strdup(name);
      if (hostent->h_name)
	{
	  hostent->h_aliases = malloc(sizeof(char *));
	  if (hostent->h_aliases)
	    {
	      hostent->h_addr_list = malloc(2 * sizeof(char *));
	      if (hostent->h_addr_list)
		{
		  hostent->h_addr_list[0] = malloc(sizeof(struct in_addr));
		  if (hostent->h_addr_list[0])
		    {
		      /* All allocations succeeded; go ahead. */
		      hostent->h_aliases[0] = NULL;
		      hostent->h_addrtype = AF_INET;
		      hostent->h_length = sizeof(struct in_addr);
		      memcpy(hostent->h_addr_list[0], &addr,
			     sizeof(struct in_addr));
		      hostent->h_addr_list[1] = NULL;
		      *host = hostent;
		      return ARES_SUCCESS;
		    }
		  free(hostent->h_addr_list);
		}
	      free(hostent->h_aliases);
	    }
	  free(hostent->h_name);
	}
      free(hostent);
    }
  return ARES_ENOMEM;
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
