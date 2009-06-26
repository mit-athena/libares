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

static const char rcsid[] = "$Id: ares_parse_a_reply.c,v 1.3 2003-09-12 00:25:17 mwhitson Exp $";

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include "ares.h"

int ares_parse_a_reply(const unsigned char *abuf, int alen,
		       struct hostent **host)
{
  int status, i, len, naddrs;
  int naliases;
  char *hostname, *rr_data, **aliases;
  struct ares_dns_message *message;
  struct ares_dns_rr *rr;
  struct in_addr *addrs;
  struct hostent *hostent;

  /* Set *host to NULL for all failure cases. */
  *host = NULL;

  status = ares_parse_message(abuf, alen, &message);
  if (status != ARES_SUCCESS)
    return status;

  if (message->qcount != 1)
    {
      ares_free_dns_message(message);
      return ARES_EBADRESP;
    }

  hostname = strdup(message->questions[0].name);
  if (!hostname)
    {
      ares_free_dns_message(message);
      return ARES_ENOMEM;
    }

  /* Allocate addresses and aliases; message->answers.count gives an
   * upper bound for both.
   */
  addrs = malloc(message->answers.count * sizeof(struct in_addr));
  if (!addrs)
    {
      ares_free_dns_message(message);
      free(hostname);
      return ARES_ENOMEM;
    }
  aliases = malloc((message->answers.count + 1) * sizeof(char *));
  if (!aliases)
    {
      ares_free_dns_message(message);
      free(hostname);
      free(addrs);
      return ARES_ENOMEM;
    }
  naddrs = 0;
  naliases = 0;

  /* Examine each answer resource record (RR) in turn. */
  for (i = 0; i < message->answers.count; i++)
    {
      rr = &message->answers.records[i];
      if (rr->dnsclass == C_IN && rr->type == T_A
	  && rr->len == sizeof(struct in_addr)
	  && strcasecmp(rr->name, hostname) == 0)
	{
	  memcpy(&addrs[naddrs], rr->data, sizeof(struct in_addr));
	  naddrs++;
	  status = ARES_SUCCESS;
	}

      if (rr->dnsclass == C_IN && rr->type == T_CNAME)
	{
	  /* Record the RR name as an alias. */
	  aliases[naliases] = strdup(rr->name);
	  if (aliases[naliases] == NULL)
	    {
	      status = ARES_ENOMEM;
	      break;
	    }
	  naliases++;

	  /* Decode the RR data and replace the hostname with it. */

	  /* ares_parse_message() resolves compression pointers in the
	   * RR data, but the data still need to be expanded.  Since
	   * we know there is no indirection, use the data buffer
	   * itself as the containing buffer. 
	   */
	  status = ares_expand_name(rr->data, rr->data, rr->len,
				    &rr_data, &len);
	  if (status != ARES_SUCCESS)
	    break;
	  free(hostname);
	  hostname = rr_data;
	}
    }

  if (status == ARES_SUCCESS && naddrs == 0)
    status = ARES_ENODATA;
  if (status == ARES_SUCCESS)
    {
      /* We got our answer.  Allocate memory to build the host entry. */
      aliases[naliases] = NULL;
      hostent = malloc(sizeof(struct hostent));
      if (hostent)
	{
	  hostent->h_addr_list = malloc((naddrs + 1) * sizeof(char *));
	  if (hostent->h_addr_list)
	    {
	      /* Fill in the hostent and return successfully. */
	      hostent->h_name = hostname;
	      hostent->h_aliases = aliases;
	      hostent->h_addrtype = AF_INET;
	      hostent->h_length = sizeof(struct in_addr);
	      for (i = 0; i < naddrs; i++)
		hostent->h_addr_list[i] = (char *) &addrs[i];
	      hostent->h_addr_list[naddrs] = NULL;
	      *host = hostent;
	      ares_free_dns_message(message);
	      return ARES_SUCCESS;
	    }
	  free(hostent);
	}
      status = ARES_ENOMEM;
    }
  for (i = 0; i < naliases; i++)
    free(aliases[i]);
  free(aliases);
  free(addrs);
  free(hostname);
  ares_free_dns_message(message);
  return status;
}
