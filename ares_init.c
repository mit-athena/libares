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

static const char rcsid[] = "$Id: ares_init.c,v 1.4 1998-09-04 21:07:29 ghudson Exp $";

#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "ares.h"
#include "ares_private.h"

struct server_ent {
  struct in_addr addr;
  struct server_ent *next;
};

static int init_by_options(ares_channel channel, struct ares_options *options,
			   int optmask);
static int init_by_environment(ares_channel channel);
static int init_by_resolv_conf(ares_channel channel);
static int init_by_defaults(ares_channel channel);
static int set_search(ares_channel channel, const char *str);
static int set_options(ares_channel channel, const char *str);
static const char *try_option(const char *p, const char *q, const char *opt);

int ares_init(ares_channel *channelptr)
{
  return ares_init_options(channelptr, NULL, 0);
}

int ares_init_options(ares_channel *channelptr, struct ares_options *options,
		      int optmask)
{
  ares_channel channel;
  int i, status;
  struct server_state *server;
  struct timeval tv;

  channel = malloc(sizeof(struct ares_channeldata));
  if (!channel)
    return ARES_ENOMEM;

  /* Set everything to distinguished values so we know they haven't
   * been set yet.
   */
  channel->flags = -1;
  channel->timeout = -1;
  channel->tries = -1;
  channel->ndots = -1;
  channel->udp_port = -1;
  channel->tcp_port = -1;
  channel->nservers = -1;
  channel->ndomains = -1;
  channel->lookups = NULL;

  /* Initialize configuration by each of the four sources, from highest
   * precedence to lowest.
   */
  status = init_by_options(channel, options, optmask);
  if (status == ARES_SUCCESS)
    status = init_by_environment(channel);
  if (status == ARES_SUCCESS)
    status = init_by_resolv_conf(channel);
  if (status == ARES_SUCCESS)
    status = init_by_defaults(channel);
  if (status != ARES_SUCCESS)
    {
      /* Something failed; clean up memory we may have allocated. */
      if (channel->nservers != -1)
	free(channel->servers);
      if (channel->ndomains != -1)
	{
	  for (i = 0; i < channel->ndomains; i++)
	    free(channel->domains[i]);
	  free(channel->domains);
	}
      if (channel->lookups)
	free(channel->lookups);
      free(channel);
      return status;
    }

  /* Trim to one server if ARES_FLAG_PRIMARY is set. */
  if ((channel->flags & ARES_FLAG_PRIMARY) && channel->nservers > 1)
    channel->nservers = 1;

  /* Initialize server states. */
  for (i = 0; i < channel->nservers; i++)
    {
      server = &channel->servers[i];
      server->udp_socket = -1;
      server->tcp_socket = -1;
      server->tcp_lenbuf_pos = 0;
      server->tcp_buffer = NULL;
      server->qhead = NULL;
      server->qtail = NULL;
    }

  /* Choose a somewhat random query ID.  The main point is to avoid
   * collisions with stale queries.  An attacker trying to spoof a DNS
   * answer also has to guess the query ID, but it's only a 16-bit
   * field, so there's not much to be done about that.
   */
  gettimeofday(&tv, NULL);
  channel->next_id = (tv.tv_sec ^ tv.tv_usec ^ getpid()) & 0xffff;

  channel->queries = NULL;

  *channelptr = channel;
  return ARES_SUCCESS;
}

static int init_by_options(ares_channel channel, struct ares_options *options,
			   int optmask)
{
  int i;

  /* Easy stuff. */
  if ((optmask & ARES_OPT_FLAGS) && channel->flags == -1)
    channel->flags = options->flags;
  if ((optmask & ARES_OPT_TIMEOUT) && channel->timeout == -1)
    channel->timeout = options->timeout;
  if ((optmask & ARES_OPT_TRIES) && channel->tries == -1)
    channel->tries = options->tries;
  if ((optmask & ARES_OPT_NDOTS) && channel->ndots == -1)
    channel->ndots = options->ndots;
  if ((optmask & ARES_OPT_UDP_PORT) && channel->udp_port == -1)
    channel->udp_port = options->udp_port;
  if ((optmask & ARES_OPT_TCP_PORT) && channel->tcp_port == -1)
    channel->tcp_port = options->tcp_port;

  /* Copy the servers, if given. */
  if ((optmask & ARES_OPT_SERVERS) && channel->nservers == -1)
    {
      channel->servers =
	malloc(options->nservers * sizeof(struct server_state));
      if (!channel->servers && options->nservers != 0)
	return ARES_ENOMEM;
      for (i = 0; i < options->nservers; i++)
	channel->servers[i].addr = options->servers[i];
      channel->nservers = options->nservers;
    }

  /* Copy the domains, if given.  Keep channel->ndomains consistent so
   * we can clean up in case of error.
   */
  if ((optmask & ARES_OPT_DOMAINS) && channel->ndomains == -1)
    {
      channel->domains = malloc(options->ndomains * sizeof(char *));
      if (!channel->domains && options->ndomains != 0)
	return ARES_ENOMEM;
      for (i = 0; i < options->ndomains; i++)
	{
	  channel->ndomains = i;
	  channel->domains[i] = strdup(options->domains[i]);
	  if (!channel->domains[i])
	    return ARES_ENOMEM;
	}
      channel->ndomains = options->ndomains;
    }

  /* Set lookups, if given. */
  if ((optmask & ARES_OPT_LOOKUPS) && !channel->lookups)
    {
      channel->lookups = strdup(options->lookups);
      if (!channel->lookups)
	return ARES_ENOMEM;
    }

  return ARES_SUCCESS;
}

static int init_by_environment(ares_channel channel)
{
  const char *localdomain, *res_options;
  int status;

  localdomain = getenv("LOCALDOMAIN");
  if (localdomain && channel->ndomains == -1)
    {
      status = set_search(channel, localdomain);
      if (status != ARES_SUCCESS)
	return status;
    }

  res_options = getenv("RES_OPTIONS");
  if (res_options)
    {
      status = set_options(channel, res_options);
      if (status != ARES_SUCCESS)
	return status;
    }

  return ARES_SUCCESS;
}

static int init_by_resolv_conf(ares_channel channel)
{
  FILE *fp;
  char *line = NULL, *p, *q, lookups[3], *l;
  int linesize, status, n = 0;
  struct server_ent *servhead = NULL, *ent;
  struct in_addr addr;

  fp = fopen(PATH_RESOLV_CONF, "r");
  if (!fp)
    return (errno == ENOENT) ? ARES_SUCCESS : ARES_EFILE;
  while ((status = ares__read_line(fp, &line, &linesize)) == ARES_SUCCESS)
    {
      if (strncmp(line, "domain", 6) == 0 && isspace(line[6])
	  && channel->ndomains == -1)
	{
	  /* Set the domain search list to a single domain. */
	  p = line + 6;
	  while (isspace(*p))
	    p++;
	  q = p;
	  while (*q && !isspace(*q))
	    q++;
	  *q = 0;
	  status = set_search(channel, p);
	  if (status != ARES_SUCCESS)
	    break;
	}
      else if (strncmp(line, "lookup", 6) == 0 && isspace(line[6])
	       && !channel->lookups)
	{
	  /* Set the lookup order.  Only the first letter of each work
	   * is relevant, and it has to be "b" for DNS or "f" for the
	   * host file.  Ignore everything else.
	   */
	  l = lookups;
	  p = line + 6;
	  while (isspace(*p))
	    p++;
	  while (*p)
	    {
	      if ((*p == 'b' || *p == 'f') && l < lookups + 2)
		*l++ = *p;
	      while (*p && !isspace(*p))
		p++;
	      while (isspace(*p))
		p++;
	    }
	  *l = 0;
	  channel->lookups = strdup(lookups);
	  if (!channel->lookups)
	    {
	      status = ARES_ENOMEM;
	      break;
	    }
	}
      else if (strncmp(line, "search", 6) == 0 && isspace(line[6])
	       && channel->ndomains == -1)
	{
	  /* Set the domain search list to one or more domains. */
	  status = set_search(channel, line + 6);
	  if (status != ARES_SUCCESS)
	    break;
	}
      else if (strncmp(line, "nameserver", 10) == 0 && isspace(line[10])
	       && channel->nservers == -1)
	{
	  /* Add a name server entry to our linked queue. */
	  p = line + 10;
	  while (isspace(*p))
	    p++;
	  addr.s_addr = inet_addr(p);
	  if (addr.s_addr == INADDR_NONE)
	    continue;
	  ent = malloc(sizeof(struct server_ent));
	  if (!ent)
	    {
	      status = ARES_ENOMEM;
	      break;
	    }
	  ent->addr = addr;
	  ent->next = servhead;
	  servhead = ent;
	  n++;
	}
      else if (strncmp(line, "options", 7) == 0 && isspace(line[7]))
	{
	  /* Set resolver options. */
	  status = set_options(channel, line + 7);
	  if (status != ARES_SUCCESS)
	    break;
	}
    }
  free(line);
  fclose(fp);

  /* If all went well and we got any servers (which only happens when
   * channel->nservers was -1 coming into this function), turn the
   * linked list of servers into an array.
   */
  if (status == ARES_EOF && servhead)
    {
      channel->servers = malloc(n * sizeof(struct server_state));
      if (channel->servers)
	{
	  channel->nservers = n;
	  for (ent = servhead; ent; ent = ent->next)
	    channel->servers[--n].addr = ent->addr;
	}
      else
	status = ARES_ENOMEM;
    }

  /* Free the linked queue. */
  while (servhead)
    {
      ent = servhead;
      servhead = servhead->next;
      free(ent);
    }

  return (status == ARES_EOF) ? ARES_SUCCESS : status;
}

static int init_by_defaults(ares_channel channel)
{
  char hostname[MAXHOSTNAMELEN + 1];

  if (channel->flags == -1)
    channel->flags = 0;
  if (channel->timeout == -1)
    channel->timeout = DEFAULT_TIMEOUT;
  if (channel->tries == -1)
    channel->tries = DEFAULT_TRIES;
  if (channel->ndots == -1)
    channel->ndots = 1;
  if (channel->udp_port == -1)
    channel->udp_port = htons(NAMESERVER_PORT);
  if (channel->tcp_port == -1)
    channel->tcp_port = htons(NAMESERVER_PORT);

  if (channel->nservers == -1)
    {
      /* If nobody specified servers, try a local named. */
      channel->servers = malloc(sizeof(struct server_state));
      if (!channel->servers)
	return ARES_ENOMEM;
      channel->servers[0].addr.s_addr = htonl(INADDR_LOOPBACK);
      channel->nservers = 1;
    }

  if (channel->ndomains == -1)
    {
      /* Derive a default domain search list from the kernel hostname,
       * or set it to empty if the hostname isn't helpful.
       */
      if (gethostname(hostname, sizeof(hostname)) == -1
	  || !strchr(hostname, '.'))
	{
	  channel->domains = malloc(0);
	  channel->ndomains = 0;
	}
      else
	{
	  channel->domains = malloc(sizeof(char *));
	  if (!channel->domains)
	    return ARES_ENOMEM;
	  channel->ndomains = 0;
	  channel->domains[0] = strdup(strchr(hostname, '.') + 1);
	  if (!channel->domains[0])
	    return ARES_ENOMEM;
	  channel->ndomains = 1;
	}
    }

  if (!channel->lookups)
    {
      channel->lookups = strdup("bf");
      if (!channel->lookups)
	return ARES_ENOMEM;
    }

  return ARES_SUCCESS;
}

static int set_search(ares_channel channel, const char *str)
{
  int n;
  const char *p, *q;

  /* Skip leading whitespace, for simplicity. */
  while (isspace(*str))
    str++;

  /* Count the domains given. */
  n = 0;
  p = str;
  while (*p)
    {
      while (*p && !isspace(*p))
	p++;
      while (isspace(*p))
	p++;
      n++;
    }

  channel->domains = malloc(n * sizeof(char *));
  if (!channel->domains && n)
    return ARES_ENOMEM;

  /* Now copy the domains. */
  n = 0;
  p = str;
  while (*p)
    {
      channel->ndomains = n;
      q = p;
      while (*q && !isspace(*q))
	q++;
      channel->domains[n] = malloc(q - p + 1);
      if (!channel->domains[n])
	return ARES_ENOMEM;
      memcpy(channel->domains[n], p, q - p);
      channel->domains[n][q - p] = 0;
      p = q;
      while (isspace(*p))
	p++;
      n++;
    }
  channel->ndomains = n;

  return ARES_SUCCESS;
}

static int set_options(ares_channel channel, const char *str)
{
  const char *p, *q, *val;

  /* Skip leading whitespace, for simplicity. */
  while (isspace(*str))
    str++;

  p = str;
  while (*p)
    {
      q = p;
      while (*q && !isspace(*q))
	q++;
      val = try_option(p, q, "ndots:");
      if (val && channel->ndots == -1)
	channel->ndots = atoi(val);
      val = try_option(p, q, "retrans:");
      if (val && channel->timeout == -1)
	channel->timeout = atoi(val);
      val = try_option(p, q, "retry:");
      if (val && channel->tries == -1)
	channel->tries = atoi(val);
      p = q;
      while (isspace(*p))
	p++;
    }

  return ARES_SUCCESS;
}

static const char *try_option(const char *p, const char *q, const char *opt)
{
  int len;

  len = strlen(opt);
  return (q - p > len && strncmp(p, opt, len) == 0) ? p + len : NULL;
}
