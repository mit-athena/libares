/* Copyright 2002 by the Massachusetts Institute of Technology.
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

static const char rcsid[] = "$Id: ares_parse_message.c,v 1.2 2002-09-10 16:03:28 ghudson Exp $";

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <netdb.h>
#include "ares.h"
#include "ares_dns.h"
#include "ares_private.h"

static const char *parse_questions(const unsigned char *aptr,
				   const unsigned char *abuf,
				   int alen, int count,
				   struct ares_dns_question **questions);
static const char *parse_question(const unsigned char *aptr,
				  const unsigned char *abuf, int alen,
				  struct ares_dns_question *question);
static const char *parse_section(const unsigned char *aptr,
				 const unsigned char *abuf, int alen,
				 struct ares_dns_section *section);
static const char *parse_rr(const unsigned char *aptr,
			    const unsigned char *abuf, int alen,
			    struct ares_dns_rr *rr);
static int parse_rr_data(const unsigned char *aptr, const unsigned char *abuf,
			 int alen, struct ares_dns_rr *rr);
static int uncompress_rr_data(const unsigned char *aptr,
			      const unsigned char *abuf, int alen,
			      const char *format, struct ares_dns_rr *rr);
static int uncompressed_length(const unsigned char *aptr, int rr_len,
			       const unsigned char *abuf, int alen,
			       const char *format);
static int domain_length(const unsigned char *aptr, const unsigned char *abuf,
			 int alen, int *cur_len, int *uncomp_len);
static void uncompress_domain(unsigned char *dest,
			      const unsigned char *aptr,
			      const unsigned char *abuf,
			      int *cur_len, int *uncomp_len);

int ares_parse_message(const unsigned char *abuf, int alen,
		       struct ares_dns_message **message)
{
  const unsigned char *aptr;
  struct ares_dns_message *msg;

  /* Set *message to NULL for all failure cases. */
  *message = NULL;

  /* Give up if abuf doesn't have room for a header. */
  if (alen < HFIXEDSZ)
    return ARES_EBADRESP;

  msg = malloc(sizeof(struct ares_dns_message));
  if (msg == NULL)
    return ARES_ENOMEM;

  /* Fill in the header fields. */
  msg->id = DNS_HEADER_QID(abuf);
  msg->is_response = DNS_HEADER_QR(abuf);
  msg->opcode = DNS_HEADER_OPCODE(abuf);
  msg->authoritative_answer = DNS_HEADER_AA(abuf);
  msg->truncated = DNS_HEADER_TC(abuf);
  msg->recursion_desired = DNS_HEADER_RD(abuf);
  msg->recursion_available = DNS_HEADER_RA(abuf);
  msg->zero = DNS_HEADER_Z(abuf);
  msg->response_code = DNS_HEADER_RCODE(abuf);
  msg->qcount = DNS_HEADER_QDCOUNT(abuf);
  msg->answers.count = DNS_HEADER_ANCOUNT(abuf);
  msg->authority.count = DNS_HEADER_NSCOUNT(abuf);
  msg->additional.count = DNS_HEADER_ARCOUNT(abuf);

  /* Initialize section records fields for easier cleanup.  No need to
   * worry about cleaning up additional, since it's the last thing we
   * do.
   */
  msg->questions = NULL;
  msg->answers.records = NULL;
  msg->authority.records = NULL;

  /* Parse the sections of resource records. */
  aptr = abuf + HFIXEDSZ;
  aptr = parse_questions(aptr, abuf, alen, msg->qcount, &msg->questions);
  if (aptr != NULL)
    aptr = parse_section(aptr, abuf, alen, &msg->answers);
  if (aptr != NULL)
    aptr = parse_section(aptr, abuf, alen, &msg->authority);
  if (aptr != NULL)
    aptr = parse_section(aptr, abuf, alen, &msg->additional);

  if (aptr == NULL)
    {
      if (msg->questions != NULL)
	ares__free_questions(msg->questions, msg->qcount);
      if (msg->answers.records != NULL)
	ares__free_section(&msg->answers);
      if (msg->authority.records != NULL)
	ares__free_section(&msg->authority);
      return ARES_EBADRESP;
    }

  *message = msg;
  return ARES_SUCCESS;
}

/* Parse the section of questions starting at aptr; return pointer to
 * the first byte after the section.  Return NULL on error.
 */
static const char *parse_questions(const unsigned char *aptr,
				   const unsigned char *abuf,
				   int alen, int count,
				   struct ares_dns_question **questions)
{
  struct ares_dns_question *quests;
  int i, j;

  /* Allocate memory for result. */
  quests = malloc(count * sizeof(struct ares_dns_rr));
  if (quests == NULL)
    return NULL;

  /* Parse each question in the section. */
  for (i = 0; i < count; i++)
    {
      aptr = parse_question(aptr, abuf, alen, &quests[i]);
      if (aptr == NULL)
	{
	  for (j = 0; j < i; j++)
	    ares__free_question(&quests[i]);
	  free(quests);
	  return NULL;
	}
    }

  *questions = quests;
  return aptr;
}

/* Parse a question starting at aptr; return pointer to the first byte
 * after the RR.  Return NULL on error.
 */
static const char *parse_question(const unsigned char *aptr,
				  const unsigned char *abuf, int alen,
				  struct ares_dns_question *question)
{
  int len, status;

  status = ares_expand_name(aptr, abuf, alen, &question->name, &len);
  if (status != ARES_SUCCESS)
    return NULL;
  aptr += len;
  if (abuf + alen - aptr >= QFIXEDSZ)
    {
      question->type = DNS_QUESTION_TYPE(aptr);
      question->dnsclass = DNS_QUESTION_CLASS(aptr);
      return aptr + QFIXEDSZ;
    }
  free(question->name);
  return NULL;
}

/* Parse a section of resource records starting at aptr; return pointer to
 * the first byte after the section.  section->count must already be set.
 * Return NULL on error.
 */
static const char *parse_section(const unsigned char *aptr,
				 const unsigned char *abuf, int alen,
				 struct ares_dns_section *section)
{
  struct ares_dns_rr *records;
  int i, j;

  /* Allocate memory for result. */
  records = malloc(section->count * sizeof(struct ares_dns_rr));
  if (records == NULL)
    return NULL;

  /* Parse each record in the section. */
  for (i = 0; i < section->count; i++)
    {
      aptr = parse_rr(aptr, abuf, alen, &records[i]);
      if (aptr == NULL)
	{
	  for (j = 0; j < i; j++)
	    ares__free_rr(&records[j]);
	  free(records);
	  return NULL;
	}
    }

  section->records = records;
  return aptr;
}

/* Parse a resource record starting at aptr; return pointer to the first
 * byte after the RR.  Return NULL on error.
 */
static const char *parse_rr(const unsigned char *aptr,
			    const unsigned char *abuf, int alen,
			    struct ares_dns_rr *rr)
{
  int len, status;

  status = ares_expand_name(aptr, abuf, alen, &rr->name, &len);
  if (status != ARES_SUCCESS)
    return NULL;
  aptr += len;
  if (abuf + alen - aptr >= RRFIXEDSZ)
    {
      rr->type = DNS_RR_TYPE(aptr);
      rr->dnsclass = DNS_RR_CLASS(aptr);
      rr->ttl = DNS_RR_TTL(aptr);
      rr->len = DNS_RR_LEN(aptr);
      aptr += RRFIXEDSZ;
      len = rr->len;
      if (parse_rr_data(aptr, abuf, alen, rr) == 0)
	return aptr + len;
    }
  free(rr->name);
  return NULL;
}

/* Some resource record types are allowed to contain compressed domain
 * names.  This set of types is fixed for all time; new resource
 * records aren't allowed to use them.  This table defines the rdata
 * formats for the record types which may contain compressed domains.
 * Format strings may contain:
 *
 *	<digit>		Fixed-length field
 *	d		Domain name (possibly compressed)
 *	s		Character string (one-byte length, then data)
 *	*		Arbitrary amount of data at end of record
 */

struct {
  int type;
  const char *format;
} ctab[] = {
  { T_CNAME,	"d" },
  { T_MB,	"d" },
  { T_MD,	"d" },
  { T_MF,	"d" },
  { T_MG,	"d" },
  { T_MINFO,	"dd" },
  { T_MR,	"d" },
  { T_MX,	"2d" },
  { T_NS,	"d" },
  { T_PTR,	"d" },
  { T_SOA,	"dd44444" },

  /* Anything beyond here shouldn't contain compressed domain names,
   * but we're supposed to do the right thing if they do.
   */
  { T_RP,	"dd" },
  { T_AFSDB,	"2d" },
  { T_RT,	"2d" },
  { T_SIG,	"2114442d*" },
  { T_PX,	"2dd" },
  { T_NXT,	"d*" },
  { T_NAPTR,	"22sssd" },
  { T_SRV,	"222d" }
};

/* Read a resource record's data into rr->data, uncompressing domain
 * names if necessary.  The other fields of rr must have already been
 * set, so that we can determine its type and length.  Reset rr->len
 * if uncompressing domains caused the length to change.  Return 0 on
 * success or -1 on failure.
 */
static int parse_rr_data(const unsigned char *aptr, const unsigned char *abuf,
			 int alen, struct ares_dns_rr *rr)
{
  int i;

  /* Length check. */
  if (abuf + alen - aptr < rr->len)
    return -1;

  /* If this record's type is in ctab, look for compressed domains. */
  for (i = 0; i < sizeof(ctab) / sizeof(*ctab); i++)
    {
      if (ctab[i].type == rr->type)
	return uncompress_rr_data(aptr, abuf, alen, ctab[i].format, rr);
    }

  /* The data is not allowed to contain compressed domains, so we can
   * just copy it.
   */
  rr->data = malloc(rr->len);
  if (rr->data == NULL && rr->len != 0)
    return -1;
  memcpy(rr->data, aptr, rr->len);
  return 0;
}

/* Take care of the difficult case of parse_rr_data(). */
static int uncompress_rr_data(const unsigned char *aptr,
			      const unsigned char *abuf, int alen,
			      const char *format, struct ares_dns_rr *rr)
{
  int ulen, uncomp_domain_len, field_len;
  const char *f;
  const unsigned char *p;
  unsigned char *q;

  /* Compute the length of the rdata with domain uncompression. */
  ulen = uncompressed_length(aptr, rr->len, abuf, alen, format);
  if (ulen == -1)
    return -1;

  rr->data = malloc(ulen);
  if (rr->data == NULL && ulen != 0)
    return -1;

  /* Now copy the data into rr->data; no error-checking is required, since
   * it was all done by uncompressed_length().
   */
  p = aptr;
  q = rr->data;
  for (f = format; *f; f++)
    {
      if (isdigit((unsigned char) *f))
	{
	  field_len = *f - '0';
	  memcpy(q, p, field_len);
	  p += field_len;
	  q += field_len;
	}
      else if (*f == 'd')
	{
	  uncompress_domain(q, p, abuf, &field_len, &uncomp_domain_len);
	  p += field_len;
	  q += uncomp_domain_len;
	}
      else if (*f == 's')
	{
	  field_len = *p;
	  memcpy(q, p, field_len + 1);
	  p += field_len + 1;
	  q += field_len + 1;
	}
      else if (*f == '*')
	memcpy(q, p, aptr + rr->len - p);
    }

  rr->len = ulen;
  return 0;
}

/* Return the length of a resource record's data (starting at aptr)
 * with all domains uncompressed.  Return -1 if the record's data is
 * malformed.
 */
static int uncompressed_length(const unsigned char *aptr, int rr_len,
			       const unsigned char *abuf, int alen,
			       const char *format)
{
  const unsigned char *p = aptr;
  const char *f;
  int dlen = 0, field_len, cur_len, uncomp_len;

  for (f = format; *f; f++)
    {
      if (isdigit((unsigned char) *f))
	{
	  field_len = *f - '0';
	  if (aptr + rr_len - p < field_len)
	    return -1;
	  p += field_len;
	  dlen += field_len;
	}
      else if (*f == 'd')
	{
	  if (domain_length(p, abuf, alen, &cur_len, &uncomp_len) == -1)
	    return -1;
	  if (aptr + rr_len - p < cur_len)
	    return -1;
	  p += cur_len;
	  dlen += uncomp_len;
	}
      else if (*f == 's')
	{
	  if (aptr + rr_len - p < 1)
	    break;
	  field_len = *p++;
	  if (aptr + rr_len - p < field_len)
	    break;
	  p += field_len;
	  dlen += field_len + 1;
	}
      else if (*f == '*')
	{
	  dlen += aptr + rr_len - p;
	  p = aptr + rr_len;
	}
    }

  /* If we didn't reach the end of the resource record data, it's
   * malformed.
   */
  if (p != aptr + rr_len)
    return -1;

  return dlen;
}

/* Examine a possibly compressed domain name and determine its current
 * and uncompressed length.  Return 0 on success or -1 if the encoded
 * domain is malformed.
 */
static int domain_length(const unsigned char *aptr, const unsigned char *abuf,
			 int alen, int *cur_len, int *uncomp_len)
{
  int n = 0, offset, indir = 0;
  const unsigned char *p = aptr;

  /* An encoded domain name must contain at least one byte. */
  if (aptr == abuf + alen)
    return -1;

  while (*p)
    {
      if ((*p & INDIR_MASK) == INDIR_MASK)
	{
	  /* If we haven't indirected yet, this is where the encoding
	   * ends as currently encoded.
	   */
	  if (indir == 0)
	    *cur_len = p + 2 - aptr;

	  /* Check the offset and go there. */
	  if (abuf + alen - p < 2)
	    return -1;
	  offset = (*p & ~INDIR_MASK) << 8 | *(p + 1);
	  if (offset >= alen)
	    return -1;
	  p = abuf + offset;

	  /* If we've seen more indirects than the message length,
	   * then there's a loop.
	   */
	  if (++indir > alen)
	    return -1;
	}
      else
	{
	  offset = *p;
	  /* There must be at least one byte for the next label. */
	  if (abuf + alen - p < offset + 2)
	    return -1;
	  p += offset + 1;
	  n += offset + 1;
	}
    }

  /* n gives the space used by all the labels in the uncompressed domain,
   * not including the 0 byte for the empty label at the end.
   */
  *uncomp_len = n + 1;

  /* If we never indirected, then p points to the 0 byte at the end of
   * the domain name as currently encoded.
   */
  if (indir == 0)
    *cur_len = p + 1 - aptr;

  return 0;
}

/* Uncompress a domain name.  No error-checking required since the
 * caller has previously taken care of that with domain_length().
 */
static void uncompress_domain(unsigned char *dest,
			      const unsigned char *aptr,
			      const unsigned char *abuf,
			      int *cur_len, int *uncomp_len)
{
  unsigned char *q = dest;
  const unsigned char *p = aptr;
  int offset, indir = 0;

  while (*p)
    {
      if ((*p & INDIR_MASK) == INDIR_MASK)
	{
	  /* If we haven't indirected yet, this is where the encoding
	   * ends as currently encoded.
	   */
	  if (!indir)
	    *cur_len = p + 2 - aptr;
	  indir = 1;

	  offset = (*p & ~INDIR_MASK) << 8 | *(p + 1);
	  p = abuf + offset;
	}
      else
	{
	  offset = *p;
	  memcpy(q, p, offset + 1);
	  p += offset + 1;
	  q += offset + 1;
	}
    }

  /* Terminate the uncompressed domain with the final empty label, and
   * store its length.
   */
  *q++ = 0;
  *uncomp_len = q - dest;

  /* If we never indirected, then p points to the 0 byte at the end of
   * the domain name as currently encoded.
   */
  if (indir == 0)
    *cur_len = p + 1 - aptr;
}
