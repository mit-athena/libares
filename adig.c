/* Copyright 1998, 2002 by the Massachusetts Institute of Technology.
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

static const char rcsid[] = "$Id: adig.c,v 1.10 2002-09-08 23:53:48 ghudson Exp $";

#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "ares.h"
#include "ares_dns.h"

#ifndef INADDR_NONE
#define	INADDR_NONE 0xffffffff
#endif

extern int optind;
extern char *optarg;

struct nv {
  const char *name;
  int value;
};

static const struct nv flags[] = {
  { "usevc",		ARES_FLAG_USEVC },
  { "primary",		ARES_FLAG_PRIMARY },
  { "igntc",		ARES_FLAG_IGNTC },
  { "norecurse",	ARES_FLAG_NORECURSE },
  { "stayopen",		ARES_FLAG_STAYOPEN },
  { "noaliases",	ARES_FLAG_NOALIASES }
};

static const struct nv classes[] = {
  { "IN",		C_IN },
  { "CHAOS",		C_CHAOS },
  { "HS",		C_HS },
  { "ANY",		C_ANY }
};

static const struct nv types[] = {
  { "A",		T_A },
  { "NS",		T_NS },
  { "MD",		T_MD },
  { "MF",		T_MF },
  { "CNAME",		T_CNAME },
  { "SOA",		T_SOA },
  { "MB",		T_MB },
  { "MG",		T_MG },
  { "MR",		T_MR },
  { "NULL",		T_NULL },
  { "WKS",		T_WKS },
  { "PTR",		T_PTR },
  { "HINFO",		T_HINFO },
  { "MINFO",		T_MINFO },
  { "MX",		T_MX },
  { "TXT",		T_TXT },
  { "RP",		T_RP },
  { "AFSDB",		T_AFSDB },
  { "X25",		T_X25 },
  { "ISDN",		T_ISDN },
  { "RT",		T_RT },
  { "NSAP",		T_NSAP },
  { "NSAP_PTR",		T_NSAP_PTR },
  { "SIG",		T_SIG },
  { "KEY",		T_KEY },
  { "PX",		T_PX },
  { "GPOS",		T_GPOS },
  { "AAAA",		T_AAAA },
  { "LOC",		T_LOC },
  { "SRV",		T_SRV },
  { "NAPTR",		T_NAPTR },
  { "AXFR",		T_AXFR },
  { "MAILB",		T_MAILB },
  { "MAILA",		T_MAILA },
  { "ANY",		T_ANY }
};

static const struct nv opcodes[] = {
  { "QUERY",		ARES_DNS_OPCODE_QUERY },
  { "IQUERY",		ARES_DNS_OPCODE_IQUERY },
  { "STATUS",		ARES_DNS_OPCODE_STATUS },
  { "(reserved)",	3 },
  { "NOTIFY",		ARES_DNS_OPCODE_NOTIFY },
  { "UPDATEA",		ARES_DNS_OPCODE_UPDATEA },
  { "UPDATED",		ARES_DNS_OPCODE_UPDATED },
  { "UPDATEDA",		ARES_DNS_OPCODE_UPDATEDA },
  { "UPDATEM",		ARES_DNS_OPCODE_UPDATEM },
  { "UPDATEMA",		ARES_DNS_OPCODE_UPDATEMA },
  { "ZONEINIT",		ARES_DNS_OPCODE_ZONEINIT },
  { "ZONEREF",		ARES_DNS_OPCODE_ZONEREF }
};

static const struct nv rcodes[] = {
  { "NOERROR",		ARES_DNS_RCODE_NOERROR },
  { "FORMERR",		ARES_DNS_RCODE_FORMERR },
  { "SERVFAIL",		ARES_DNS_RCODE_SERVFAIL },
  { "NXDOMAIN",		ARES_DNS_RCODE_NXDOMAIN },
  { "NOTIMP",		ARES_DNS_RCODE_NOTIMP },
  { "REFUSED",		ARES_DNS_RCODE_REFUSED },
  { "NOCHANGE",		ARES_DNS_RCODE_NOCHANGE }
};

static void callback(void *arg, int status, unsigned char *abuf, int alen);
static void display_question(struct ares_dns_question *question);
static void display_rr(struct ares_dns_rr *rr);
static const char *nvtab_name(int value, const struct nv *table, int len);
static int nvtab_value(const char *str, const struct nv *table, int len);
static const char *type_name(int type);
static const char *class_name(int dnsclass);
static const char *opcode_name(int dnsclass);
static const char *rcode_name(int dnsclass);
static int flag_value(const char *dnsclass);
static int class_value(const char *dnsclass);
static int type_value(const char *type);
static void usage(void);

int main(int argc, char **argv)
{
  ares_channel channel;
  int c, i, optmask = ARES_OPT_FLAGS, dnsclass = C_IN, type = T_A;
  int status, nfds, count;
  struct ares_options options;
  struct hostent *hostent;
  fd_set read_fds, write_fds;
  struct timeval *tvp, tv;
  char *errmem;

  options.flags = ARES_FLAG_NOCHECKRESP;
  options.servers = NULL;
  options.nservers = 0;
  while ((c = getopt(argc, argv, "f:s:c:t:T:U:")) != -1)
    {
      switch (c)
	{
	case 'f':
	  /* Add a flag. */
	  i = flag_value(optarg);
	  if (i == -1)
	    usage();
	  options.flags |= i;
	  break;

	case 's':
	  /* Add a server, and specify servers in the option mask. */
	  hostent = gethostbyname(optarg);
	  if (!hostent || hostent->h_addrtype != AF_INET)
	    {
	      fprintf(stderr, "adig: server %s not found.\n", optarg);
	      return 1;
	    }
	  options.servers = realloc(options.servers, (options.nservers + 1)
				    * sizeof(struct in_addr));
	  if (!options.servers)
	    {
	      fprintf(stderr, "Out of memory!\n");
	      return 1;
	    }
	  memcpy(&options.servers[options.nservers], hostent->h_addr,
		 sizeof(struct in_addr));
	  options.nservers++;
	  optmask |= ARES_OPT_SERVERS;
	  break;

	case 'c':
	  /* Set the query class. */
	  dnsclass = class_value(optarg);
	  if (dnsclass == -1)
	    usage();
	  break;

	case 't':
	  /* Set the query type. */
	  type = type_value(optarg);
	  if (type == -1)
	    usage();
	  break;

	case 'T':
	  /* Set the TCP port number. */
	  if (!isdigit((unsigned char)*optarg))
	    usage();
	  options.tcp_port = strtol(optarg, NULL, 0);
	  optmask |= ARES_OPT_TCP_PORT;
	  break;

	case 'U':
	  /* Set the UDP port number. */
	  if (!isdigit((unsigned char)*optarg))
	    usage();
	  options.udp_port = strtol(optarg, NULL, 0);
	  optmask |= ARES_OPT_UDP_PORT;
	  break;
	}
    }
  argc -= optind;
  argv += optind;
  if (argc == 0)
    usage();

  status = ares_init_options(&channel, &options, optmask);
  if (status != ARES_SUCCESS)
    {
      fprintf(stderr, "ares_init_options: %s\n",
	      ares_strerror(status, &errmem));
      ares_free_errmem(errmem);
      return 1;
    }

  /* Initiate the queries, one per command-line argument.  If there is
   * only one query to do, supply NULL as the callback argument;
   * otherwise, supply the query name as an argument so we can
   * distinguish responses for the user when printing them out.
   */
  if (argc == 1)
    ares_query(channel, *argv, dnsclass, type, callback, (char *) NULL);
  else
    {
      for (; *argv; argv++)
	ares_query(channel, *argv, dnsclass, type, callback, *argv);
    }

  /* Wait for all queries to complete. */
  while (1)
    {
      FD_ZERO(&read_fds);
      FD_ZERO(&write_fds);
      nfds = ares_fds(channel, &read_fds, &write_fds);
      if (nfds == 0)
	break;
      tvp = ares_timeout(channel, NULL, &tv);
      count = select(nfds, &read_fds, &write_fds, NULL, tvp);
      if (count < 0 && errno != EINVAL)
	{
	  perror("select");
	  return 1;
	}
      ares_process(channel, &read_fds, &write_fds);
    }

  ares_destroy(channel);
  return 0;
}

static void callback(void *arg, int status, unsigned char *abuf, int alen)
{
  char *name = (char *) arg, *errmem;
  struct ares_dns_message *message;
  int i;

  /* Display the query name if given. */
  if (name)
    printf("Answer for query %s:\n", name);

  /* Display an error message if there was an error, but only stop if
   * we actually didn't get an answer buffer.
   */
  if (status != ARES_SUCCESS)
    {
      printf("%s\n", ares_strerror(status, &errmem));
      ares_free_errmem(errmem);
      if (!abuf)
	return;
    }

  status = ares_parse_message(abuf, alen, &message);
  if (status != ARES_SUCCESS)
    {
      printf("%s\n", ares_strerror(status, &errmem));
      ares_free_errmem(errmem);
      return;
    }

  /* Display the answer header. */
  printf("id: %d\n", message->id);
  printf("flags: %s%s%s%s%s\n",
	 message->is_response ? "qr " : "",
	 message->authoritative_answer ? "aa " : "",
	 message->truncated ? "tc " : "",
	 message->recursion_desired ? "rd " : "",
	 message->recursion_available ? "ra " : "");
  printf("opcode: %s\n", opcode_name(message->opcode));
  printf("rcode: %s\n", rcode_name(message->response_code));

  /* Display the questions and RR sections. */
  printf("Questions:\n");
  for (i = 0; i < message->qcount; i++)
    display_question(&message->questions[i]);
  printf("Answers:\n");
  for (i = 0; i < message->answers.count; i++)
    display_rr(&message->answers.records[i]);
  printf("NS records:\n");
  for (i = 0; i < message->authority.count; i++)
    display_rr(&message->authority.records[i]);
  printf("Additional records:\n");
  for (i = 0; i < message->additional.count; i++)
    display_rr(&message->additional.records[i]);

  ares_free_dns_message(message);
}

static void display_question(struct ares_dns_question *question)
{
  printf("\t%-15s.\t", question->name);
  if (question->dnsclass != C_IN)
    printf("\t%s", class_name(question->dnsclass));
  printf("\t%s\n", type_name(question->type));
}

static void display_rr(struct ares_dns_rr *rr)
{
  const unsigned char *p;
  char *name;
  int status, len;
  struct in_addr addr;

  /* Display the RR name, class, and type. */
  printf("\t%-15s.\t%d", rr->name, rr->ttl);
  if (rr->dnsclass != C_IN)
    printf("\t%s", class_name(rr->dnsclass));
  printf("\t%s", type_name(rr->type));

  /* Display the RR data.  Don't touch aptr. */
  switch (rr->type)
    {
    case T_CNAME:
    case T_MB:
    case T_MD:
    case T_MF:
    case T_MG:
    case T_MR:
    case T_NS:
    case T_PTR:
      /* For these types, the RR data is just a domain name. */
      status = ares_expand_name(rr->data, rr->data, rr->len, &name, &len);
      if (status != ARES_SUCCESS)
	return;
      printf("\t%s.", name);
      ares_free_string(name);
      break;

    case T_HINFO:
      /* The RR data is two length-counted character strings. */
      p = rr->data;
      len = *p;
      if (rr->data + rr->len - p < len + 1)
	return;
      printf("\t%.*s", len, p + 1);
      p += len + 1;
      len = *p;
      if (rr->data + rr->len - p < len + 1)
	return;
      printf("\t%.*s", len, p + 1);
      break;

    case T_MINFO:
      /* The RR data is two domain names. */
      p = rr->data;
      status = ares_expand_name(p, rr->data, rr->len, &name, &len);
      if (status != ARES_SUCCESS)
	return;
      printf("\t%s.", name);
      ares_free_string(name);
      p += len;
      status = ares_expand_name(p, rr->data, rr->len, &name, &len);
      if (status != ARES_SUCCESS)
	return;
      printf("\t%s.", name);
      ares_free_string(name);
      break;

    case T_MX:
      /* The RR data is two bytes giving a preference ordering, and
       * then a domain name.
       */
      if (rr->len < 2)
	return;
      printf("\t%d", (rr->data[0] << 8) | rr->data[1]);
      status = ares_expand_name(rr->data + 2, rr->data, rr->len, &name, &len);
      if (status != ARES_SUCCESS)
	return;
      printf("\t%s.", name);
      ares_free_string(name);
      break;

    case T_SOA:
      /* The RR data is two domain names and then five four-byte
       * numbers giving the serial number and some timeouts.
       */
      p = rr->data;
      status = ares_expand_name(p, rr->data, rr->len, &name, &len);
      if (status != ARES_SUCCESS)
	return;
      printf("\t%s.\n", name);
      ares_free_string(name);
      p += len;
      status = ares_expand_name(p, rr->data, rr->len, &name, &len);
      if (status != ARES_SUCCESS)
	return;
      printf("\t\t\t\t\t\t%s.\n", name);
      ares_free_string(name);
      p += len;
      if (rr->data + rr->len - p < 20)
	return;
      printf("\t\t\t\t\t\t( %d %d %d %d %d )",
	     (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3],
	     (p[4] << 24) | (p[5] << 16) | (p[6] << 8) | p[7],
	     (p[8] << 24) | (p[9] << 16) | (p[10] << 8) | p[11],
	     (p[12] << 24) | (p[13] << 16) | (p[14] << 8) | p[15],
	     (p[16] << 24) | (p[17] << 16) | (p[18] << 8) | p[19]);
      break;

    case T_TXT:
      /* The RR data is one or more length-counted character
       * strings. */
      p = rr->data;
      while (rr->data + rr->len - p > 0)
	{
	  len = *p;
	  if (rr->data + rr->len - p < len + 1)
	    return;
	  printf("\t%.*s", len, p + 1);
	  p += len + 1;
	}
      break;

    case T_A:
      /* The RR data is a four-byte Internet address. */
      if (rr->len != 4)
	return;
      memcpy(&addr, rr->data, sizeof(struct in_addr));
      printf("\t%s", inet_ntoa(addr));
      break;

    case T_WKS:
      /* Not implemented yet */
      break;

    case T_SRV:
      /* The RR data is three two-byte numbers representing the
       * priority, weight, and port, followed by a domain name.
       */

      if (rr->len < 6)
	return;
      p = rr->data;
      printf("\t%d", (p[0] << 8) | p[1]);
      printf(" %d", (p[2] << 8) | p[3]);
      printf(" %d", (p[4] << 8) | p[5]);

      status = ares_expand_name(rr->data + 6, rr->data, rr->len, &name, &len);
      if (status != ARES_SUCCESS)
        return;
      printf("\t%s.", name);
      ares_free_string(name);
      break;
      
    default:
      printf("\t[Unknown RR; cannot parse]");
    }
  printf("\n");
}

static const char *nvtab_name(int value, const struct nv *table, int len)
{
  int i;

  for (i = 0; i < len; i++)
    {
      if (table[i].value == value)
	return types[i].name;
    }
  return "(unknown)";
}

static int nvtab_value(const char *str, const struct nv *table, int len)
{
  int i;

  for (i = 0; i < len; i++)
    {
      if (strcasecmp(table[i].name, str) == 0)
	return table[i].value;
    }
  return -1;
}

static const char *type_name(int type)
{
  return nvtab_name(type, types, sizeof(types) / sizeof(*types));
}

static const char *class_name(int dnsclass)
{
  return nvtab_name(dnsclass, classes, sizeof(classes) / sizeof(*classes));
}

static const char *opcode_name(int opcode)
{
  return nvtab_name(opcode, opcodes, sizeof(opcodes) / sizeof(*opcodes));
}

static const char *rcode_name(int rcode)
{
  return nvtab_name(rcode, rcodes, sizeof(rcodes) / sizeof(*rcodes));
}

static int flag_value(const char *flag)
{
  return nvtab_value(flag, flags, sizeof(flags) / sizeof(*flags));
}

static int class_value(const char *dnsclass)
{
  return nvtab_value(dnsclass, classes, sizeof(classes) / sizeof(*classes));
}

static int type_value(const char *type)
{
  return nvtab_value(type, types, sizeof(types) / sizeof(*types));
}

static void usage(void)
{
  fprintf(stderr, "usage: adig [-f flag] [-s server] [-c class] "
	  "[-t type] [-p port] name ...\n");
  exit(1);
}
