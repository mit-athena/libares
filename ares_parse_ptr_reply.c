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

static const char rcsid[] = "$Id: ares_parse_ptr_reply.c,v 1.4 2003-09-12 00:25:17 mwhitson Exp $";

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include "ares.h"

int ares_parse_ptr_reply(const unsigned char *abuf, int alen, const void *addr,
			 int addrlen, int family, struct hostent **host)
{
  int status, i, len;
  char *ptrname, *hostname, *rr_data;
  struct ares_dns_message *message;
  struct ares_dns_rr *rr;
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

  ptrname = strdup(message->questions[0].name);
  if (!ptrname)
    {
      ares_free_dns_message(message);
      return ARES_ENOMEM;
    }

  /* Examine each answer resource record (RR) in turn. */
  hostname = NULL;
  for (i = 0; i < message->answers.count; i++)
    {
      rr = &message->answers.records[i];
      if (rr->dnsclass == C_IN && rr->type == T_PTR
	  && strcasecmp(rr->name, ptrname) == 0)
	{
	  /* Decode the RR data and set hostname to it. */

	  /* ares_parse_message() resolves compression pointers in the
	   * RR data, but the data still need to be expanded.  Since
	   * we know there is no indirection, use the data buffer
	   * itself as the containing buffer. 
	   */
	  status = ares_expand_name(rr->data, rr->data, rr->len, 
				    &rr_data, &len);
	  if (status != ARES_SUCCESS)
	    break;
	  if (hostname)
	    free(hostname);
	  hostname = rr_data;
	}

      if (rr->dnsclass == C_IN && rr->type == T_CNAME)
	{
	  /* Decode the RR data and replace ptrname with it. */
	  status = ares_expand_name(rr->data, rr->data, rr->len,
				    &rr_data, &len);
	  if (status != ARES_SUCCESS)
	    break;
	  free(ptrname);
	  ptrname = rr_data;
	}
    }

  if (status == ARES_SUCCESS && !hostname)
    status = ARES_ENODATA;
  if (status == ARES_SUCCESS)
    {
      /* We got our answer.  Allocate memory to build the host entry. */
      hostent = malloc(sizeof(struct hostent));
      if (hostent)
	{
	  hostent->h_addr_list = malloc(2 * sizeof(char *));
	  if (hostent->h_addr_list)
	    {
	      hostent->h_addr_list[0] = malloc(addrlen);
	      if (hostent->h_addr_list[0])
		{
		  hostent->h_aliases = malloc(sizeof (char *));
		  if (hostent->h_aliases)
		    {
		      /* Fill in the hostent and return successfully. */
		      hostent->h_name = hostname;
		      hostent->h_aliases[0] = NULL;
		      hostent->h_addrtype = family;
		      hostent->h_length = addrlen;
		      memcpy(hostent->h_addr_list[0], addr, addrlen);
		      hostent->h_addr_list[1] = NULL;
		      *host = hostent;
		      free(ptrname);
		      ares_free_dns_message(message);
		      return ARES_SUCCESS;
		    }
		  free(hostent->h_addr_list[0]);
		}
	      free(hostent->h_addr_list);
	    }
	  free(hostent);
	}
      status = ARES_ENOMEM;
    }
  ares_free_dns_message(message);
  if (hostname)
    free(hostname);
  free(ptrname);
  return status;
}
