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

static const char rcsid[] = "$Id: ares_free_dns_message.c,v 1.1 2002-09-08 23:53:50 ghudson Exp $";

#include <stdlib.h>
#include "ares.h"
#include "ares_private.h"

void ares_free_dns_message(struct ares_dns_message *message)
{
  ares__free_questions(message->questions, message->qcount);
  ares__free_section(&message->answers);
  ares__free_section(&message->authority);
  ares__free_section(&message->additional);
}

void ares__free_questions(struct ares_dns_question *questions, int count)
{
  int i;

  for (i = 0; i < count; i++)
    ares__free_question(&questions[i]);
  free(questions);
}

void ares__free_question(struct ares_dns_question *question)
{
  free(question->name);
}

void ares__free_section(struct ares_dns_section *section)
{
  int i;

  for (i = 0; i < section->count; i++)
    ares__free_rr(&section->records[i]);
  free(section->records);
}

void ares__free_rr(struct ares_dns_rr *rr)
{
  free(rr->name);
  free(rr->data);
}

