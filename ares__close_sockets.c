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

static const char rcsid[] = "$Id: ares__close_sockets.c,v 1.2 2002-04-04 14:01:52 ghudson Exp $";

#include <stdlib.h>
#include <unistd.h>
#include "ares.h"
#include "ares_private.h"

void ares__close_sockets(struct server_state *server)
{
  struct send_request *sendreq;

  /* Free all pending output buffers. */
  while (server->qhead)
    {
      /* Advance server->qhead; pull out query as we go. */
      sendreq = server->qhead;
      server->qhead = sendreq->next;
      free(sendreq);
    }
  server->qtail = NULL;

  /* Reset any existing input buffer. */
  if (server->tcp_buffer)
    free(server->tcp_buffer);
  server->tcp_buffer = NULL;
  server->tcp_lenbuf_pos = 0;

  /* Close the TCP and UDP sockets. */
  if (server->tcp_socket != -1)
    {
      close(server->tcp_socket);
      server->tcp_socket = -1;
    }
  if (server->udp_socket != -1)
    {
      close(server->udp_socket);
      server->udp_socket = -1;
    }

  /* Clear readable/writable flags, since we might be in the middle of
   * an ares_process() run.
   */
  server->udp_readable = 0;
  server->tcp_readable = 0;
  server->tcp_writable = 0;
}
