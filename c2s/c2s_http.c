/* vim: set et ts=4 sw=4: */
/*
 * jabberd - Jabber Open Source Server
 * Copyright (c) 2002 Jeremie Miller, Thomas Muldowney,
 *                    Ryan Eatmon, Robert Norris
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA02111-1307USA
 */

#include "c2s.h"
#include <stringprep.h>


static C2S_API void _c2s_bosh_socket_close(bosh_socket_t bosh_sock);
static C2S_API sess_t _c2s_bosh_get_session_for_client(bosh_socket_t presess, char* sid);
static C2S_API sess_t _c2s_bosh_create_session_for_client(bosh_socket_t presess, unsigned int rid);
static C2S_API int _c2s_bosh_queue_data(sess_t sess, char* bodyattrdata, int bodyattrlen, int canwrite_sx, int writeisoptional);
static C2S_API int _sx_server_bosh_stream_restart(void *arg, const char *to, const char* version);
static C2S_API int _sx_bosh_read(sx_t s, char* in_buf, int read);
static C2S_API void _c2s_bosh_session_term(sess_t sess, char* termmsg);
static C2S_API int _c2s_bosh_write_data(sess_t sess, char* bodyattrdata, int bodyattrlen, int canreceive_sx, int writeisoptional);
static C2S_API int c2s_bosh_process_read_data(bosh_socket_t bosh_sock);
static C2S_API int _c2s_bosh_sock_write(bosh_socket_t bosh_sock, sx_buf_t sx_buf);
static C2S_API int _c2s_bosh_sock_read(bosh_socket_t bosh_sock);
static C2S_API int c2s_bosh_prebind_startsession(bosh_socket_t bosh_sock, nad_t nad);
static C2S_API void c2s_bosh_prebind_bindsession(bosh_socket_t bosh_sock, const char* resource);

#ifdef HAVE_SSL
static C2S_API void _c2s_bosh_ssl_free_for_client(bosh_socket_t bosh_sock);
static C2S_API void _c2s_bosh_ssl_init_for_client(bosh_socket_t bosh_sock);
#endif

static int _c2s_client_bosh_sx_callback(sx_t s, sx_event_t e, void *data, void *arg) {
    sess_t sess = (sess_t) arg;
    sx_buf_t buf = (sx_buf_t) data;
    int len, ns, elem, attr;
    sx_error_t *sxe;
    nad_t nad;
    char root[9];
    bres_t bres, ires;
    stream_redirect_t redirect;

    switch(e) {
        case event_WANT_READ:
            log_debug(ZONE, "want read");

            if(sess->bosh->connection1 != NULL)
            { //Readable connection
                mio_read(sess->c2s->mio, sess->bosh->connection1->fd);
            }

            if(sess->bosh->connection2 != NULL)
            { //Readable connection
                mio_read(sess->c2s->mio, sess->bosh->connection2->fd);
            }

            break;

        case event_WANT_WRITE:
            log_debug(ZONE, "want write");

            if(sess->bosh->sendbuf != NULL)
            {   //Only trigger mio_write()
                _c2s_bosh_write_data(sess, NULL, 0, 0, 1);
                break;
            }

            //Don't fill the buffer if we have no active socket. Doing it later is better
            if((sess->bosh->connection1 != NULL && sess->bosh->connection1->waitpoint != 0) ||
                 (sess->bosh->connection2 != NULL && sess->bosh->connection2->waitpoint != 0)){

                _c2s_bosh_write_data(sess, NULL, 0, 1, 1);

            }
            break;

        case event_READ:
            //This is dead
            return 0;

        case event_WRITE:
            log_debug(ZONE, "writing to %s", sess->skey);
            //Writing to BOSH output buffer
            len = buf->len;

            if(len > 1024)
                len = 1024;

            if(sess->bosh->sx_buf != NULL)
            {
                memcpy(sess->bosh->sx_buf, buf->data, len);
                sess->bosh->sx_buflen = len;
                return len;

            }
            sess->bosh->sx_buflen = 0;

            if(s->state >= state_OPEN && sess->resources != NULL)
                log_write(sess->c2s->log, LOG_NOTICE, "[%s] [%s] write error: %s (%d)", sess->skey, jid_user(sess->resources->jid), MIO_STRERROR(MIO_ERROR), MIO_ERROR);
            else
                log_write(sess->c2s->log, LOG_NOTICE, "[%s] [%s] write error: %s (%d)", sess->skey, sess->ip, MIO_STRERROR(MIO_ERROR), MIO_ERROR);

            sx_kill(s);

            return -1;

        case event_ERROR:
            sxe = (sx_error_t *) data;
            if(sess->resources != NULL)
                log_write(sess->c2s->log, LOG_NOTICE, "[%s] [%s] error: %s (%s)", sess->skey, jid_user(sess->resources->jid), sxe->generic, sxe->specific);
            else
                log_write(sess->c2s->log, LOG_NOTICE, "[%s] [%s] error: %s (%s)", sess->skey, sess->ip, sxe->generic, sxe->specific);

            break;

        case event_STREAM:


            if(s->req_to == NULL) {
                log_debug(ZONE, "no stream to provided, closing");
                sx_error(s, stream_err_HOST_UNKNOWN, "no 'to' attribute on stream header");
                sx_close(s);

                return 0;
            }

            /* send a see-other-host error if we're configured to do so */
            redirect = (stream_redirect_t) xhash_get(sess->c2s->stream_redirects, s->req_to);
            if (redirect != NULL) {
                log_debug(ZONE, "redirecting client's stream using see-other-host for domain: '%s'", s->req_to);
                len = strlen(redirect->to_address) + strlen(redirect->to_port) + 1;
                char *other_host = (char *) malloc(len+1);
                snprintf(other_host, len+1, "%s:%s", redirect->to_address, redirect->to_port);
                sx_error_extended(s, stream_err_SEE_OTHER_HOST, other_host);
                free(other_host);
                sx_close(s);
                return 0;
            }

            /* setup the host */
            sess->host = xhash_get(sess->c2s->hosts, s->req_to);

            if(sess->host == NULL && sess->c2s->vhost == NULL) {
                log_debug(ZONE, "no host available for requested domain '%s'", s->req_to);
                sx_error(s, stream_err_HOST_UNKNOWN, "service requested for unknown domain");
                sx_close(s);

                return 0;
            }

            if(xhash_get(sess->c2s->sm_avail, s->req_to) == NULL) {
                log_debug(ZONE, "sm for domain '%s' is not online", s->req_to);
                sx_error(s, stream_err_HOST_GONE, "session manager for requested domain is not available");
                sx_close(s);

                return 0;
            }

            if(sess->host == NULL) {
                /* create host on-fly */
                sess->host = (host_t) pmalloc(xhash_pool(sess->c2s->hosts), sizeof(struct host_st));
                memcpy(sess->host, sess->c2s->vhost, sizeof(struct host_st));
                sess->host->realm = pstrdup(xhash_pool(sess->c2s->hosts), s->req_to);
                xhash_put(sess->c2s->hosts, pstrdup(xhash_pool(sess->c2s->hosts), s->req_to), sess->host);
            }

#ifdef HAVE_SSL
            //No STARTTLS for BOSH connections. Maybe it has to be disabled somewhere else as well
#endif
            break;

        case event_PACKET:

            /* we're counting packets */
            sess->packet_count++;
            sess->c2s->packet_count++;

            /* check rate limits */
            if(sess->stanza_rate != NULL) {
                if(rate_check(sess->stanza_rate) == 0) {

                    /* inform the app if we haven't already */
                    if(!sess->stanza_rate_log) {
                        if(s->state >= state_STREAM && sess->resources != NULL)
                            log_write(sess->c2s->log, LOG_NOTICE, "[%d] [%s] is being stanza rate limited", sess->skey, jid_user(sess->resources->jid));
                        else
                            log_write(sess->c2s->log, LOG_NOTICE, "[%s] [%s] is being stanza rate limited", sess->skey, sess->ip);

                        sess->stanza_rate_log = 1;
                    }
                }

                /* update rate limits */
                rate_add(sess->stanza_rate, 1);
            }

            nad = (nad_t) data;

            /* we only want (message|presence|iq) in jabber:client, everything else gets dropped */
            snprintf(root, 9, "%.*s", NAD_ENAME_L(nad, 0), NAD_ENAME(nad, 0));
            if(NAD_ENS(nad, 0) != nad_find_namespace(nad, 0, uri_CLIENT, NULL) ||
               (strcmp(root, "message") != 0 && strcmp(root, "presence") != 0 && strcmp(root, "iq") != 0)) {
                nad_free(nad);
                return 0;
            }

            /* resource bind */
            if((ns = nad_find_scoped_namespace(nad, uri_BIND, NULL)) >= 0 && (elem = nad_find_elem(nad, 0, ns, "bind", 1)) >= 0 && nad_find_attr(nad, 0, -1, "type", "set") >= 0) {
                bres_t bres;
                jid_t jid = jid_new(sess->s->auth_id, -1);

                /* get the resource */
                elem = nad_find_elem(nad, elem, ns, "resource", 1);

                /* user-specified resource */
                if(elem >= 0) {
                    char resource_buf[1024];

                    if(NAD_CDATA_L(nad, elem) == 0) {
                        log_debug(ZONE, "empty resource specified on bind");
                        sx_nad_write(sess->s, stanza_error(nad, 0, stanza_err_BAD_REQUEST));

                        return 0;
                    }

                    snprintf(resource_buf, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
                    /* Put resource into JID */
                    if (jid == NULL || jid_reset_components(jid, jid->node, jid->domain, resource_buf) == NULL) {
                        log_debug(ZONE, "invalid jid data");
                        sx_nad_write(sess->s, stanza_error(nad, 0, stanza_err_BAD_REQUEST));

                        return 0;
                    }

                    /* check if resource already bound */
                    for(bres = sess->resources; bres != NULL; bres = bres->next)
                        if(strcmp(bres->jid->resource, jid->resource) == 0){
                            log_debug(ZONE, "resource /%s already bound - generating", jid->resource);
                            jid_random_part(jid, jid_RESOURCE);
                        }
                }
                else {
                    /* generate random resource */
                    log_debug(ZONE, "no resource given - generating");
                    jid_random_part(jid, jid_RESOURCE);
                }

                /* attach new bound jid holder */
                bres = (bres_t) calloc(1, sizeof(struct bres_st));
                bres->jid = jid;
                if(sess->resources != NULL) {
                    for(ires = sess->resources; ires->next != NULL; ires = ires->next);
                    ires->next = bres;
                } else
                    sess->resources = bres;

                sess->bound += 1;

                log_write(sess->c2s->log, LOG_NOTICE, "[%d] bound: jid=%s", sess->s->tag, jid_full(bres->jid));

                /* build a result packet, we'll send this back to the client after we have a session for them */
                sess->result = nad_new();

                ns = nad_add_namespace(sess->result, uri_CLIENT, NULL);

                nad_append_elem(sess->result, ns, "iq", 0);
                nad_set_attr(sess->result, 0, -1, "type", "result", 6);

                attr = nad_find_attr(nad, 0, -1, "id", NULL);
                if(attr >= 0)
                    nad_set_attr(sess->result, 0, -1, "id", NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

                ns = nad_add_namespace(sess->result, uri_BIND, NULL);

                nad_append_elem(sess->result, ns, "bind", 1);
                nad_append_elem(sess->result, ns, "jid", 2);
                nad_append_cdata(sess->result, jid_full(bres->jid), strlen(jid_full(bres->jid)), 3);

                /* our local id */
                strncpy(bres->c2s_id, sess->skey, sizeof(bres->c2s_id));
                bres->c2s_id[sizeof(bres->c2s_id) -1] = 0;

                /* start a session with the sm */
                sm_start(sess, bres);

                /* finished with the nad */
                nad_free(nad);

                /* handled */
                return 0;
            }

            /* resource unbind */
            if((ns = nad_find_scoped_namespace(nad, uri_BIND, NULL)) >= 0 && (elem = nad_find_elem(nad, 0, ns, "unbind", 1)) >= 0 && nad_find_attr(nad, 0, -1, "type", "set") >= 0) {
                char resource_buf[1024];
                bres_t bres;

                /* get the resource */
                elem = nad_find_elem(nad, elem, ns, "resource", 1);

                if(elem < 0 || NAD_CDATA_L(nad, elem) == 0) {
                    log_debug(ZONE, "no/empty resource given to unbind");
                    sx_nad_write(sess->s, stanza_error(nad, 0, stanza_err_BAD_REQUEST));

                    return 0;
                }

                snprintf(resource_buf, 1024, "%.*s", NAD_CDATA_L(nad, elem), NAD_CDATA(nad, elem));
                if(stringprep_xmpp_resourceprep(resource_buf, 1024) != 0) {
                    log_debug(ZONE, "cannot resourceprep");
                    sx_nad_write(sess->s, stanza_error(nad, 0, stanza_err_BAD_REQUEST));

                    return 0;
                }

                /* check if resource bound */
                for(bres = sess->resources; bres != NULL; bres = bres->next)
                    if(strcmp(bres->jid->resource, resource_buf) == 0)
                        break;

                if(bres == NULL) {
                    log_debug(ZONE, "resource /%s not bound", resource_buf);
                    sx_nad_write(sess->s, stanza_error(nad, 0, stanza_err_ITEM_NOT_FOUND));

                    return 0;
                }

                /* build a result packet, we'll send this back to the client after we close a session for them */
                sess->result = nad_new();

                ns = nad_add_namespace(sess->result, uri_CLIENT, NULL);

                nad_append_elem(sess->result, ns, "iq", 0);
                nad_set_attr(sess->result, 0, -1, "type", "result", 6);

                attr = nad_find_attr(nad, 0, -1, "id", NULL);
                if(attr >= 0)
                    nad_set_attr(sess->result, 0, -1, "id", NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr));

                /* end a session with the sm */
                sm_end(sess, bres);

                /* finished with the nad */
                nad_free(nad);

                /* handled */
                return 0;
            }

            /* pre-session requests */
            if(!sess->active && sess->sasl_authd && sess->result == NULL && strcmp(root, "iq") == 0 && nad_find_attr(nad, 0, -1, "type", "set") >= 0) {
                log_debug(ZONE, "unrecognised pre-session packet, bye");
                log_write(sess->c2s->log, LOG_NOTICE, "[%d] unrecognized pre-session packet, closing stream", sess->s->tag);

                sx_error(s, stream_err_NOT_AUTHORIZED, "unrecognized pre-session stanza");
                sx_close(s);

                nad_free(nad);
                return 0;
            }

#ifdef HAVE_SSL
            /* drop packets if they have to starttls and they haven't */
            /* No STARTTLS in BOSH */
#endif

            /* handle iq:auth packets */
            if(authreg_process(sess->c2s, sess, nad) == 0)
                return 0;

            /* drop it if no session */
            if(!sess->active) {
                log_debug(ZONE, "pre-session packet, bye");
                log_write(sess->c2s->log, LOG_NOTICE, "[%d] packet sent before session start, closing stream", sess->s->tag);

                sx_error(s, stream_err_NOT_AUTHORIZED, "stanza sent before session start");
                sx_close(s);

                nad_free(nad);
                return 0;
            }

            /* validate 'from' */
            assert(sess->resources != NULL);
            if(sess->bound > 1) {
                bres = NULL;
                if((attr = nad_find_attr(nad, 0, -1, "from", NULL)) >= 0)
                    for(bres = sess->resources; bres != NULL; bres = bres->next)
                        if(strncmp(jid_full(bres->jid), NAD_AVAL(nad, attr), NAD_AVAL_L(nad, attr)) == 0)
                            break;

                if(bres == NULL) {
                    if(attr >= 0) {
                        log_debug(ZONE, "packet from: %.*s that has not bound the resource", NAD_AVAL_L(nad, attr), NAD_AVAL(nad, attr));
                    } else {
                        log_debug(ZONE, "packet without 'from' on multiple resource stream");
                    }

                    sx_nad_write(sess->s, stanza_error(nad, 0, stanza_err_UNKNOWN_SENDER));

                    return 0;
                }
            } else
                bres = sess->resources;

            /* pass it on to the session manager */
            sm_packet(sess, bres, nad);

            break;

        case event_OPEN:

            /* only send a result and bring us online if this wasn't a sasl auth */
            if(strlen(s->auth_method) < 4 || strncmp("SASL", s->auth_method, 4) != 0) {
                /* return the auth result to the client */
                sx_nad_write(s, sess->result);
                sess->result = NULL;

                /* we're good to go */
                sess->active = 1;
            }

            /* they sasl auth'd, so we only want the new-style session start */
            else {
                log_write(sess->c2s->log, LOG_NOTICE, "[%d] %s authentication succeeded: %s %s%s%s",
                    sess->s->tag, &sess->s->auth_method[5],
                    sess->s->auth_id, sess->s->ip,
                    sess->s->ssf ? " TLS" : "", sess->s->compressed ? " ZLIB" : ""
                );
                sess->sasl_authd = 1;
            }

            break;

        case event_CLOSED:
            _c2s_bosh_session_term(sess, NULL);
            return -1;
    }

    return 0;
}


static void print_bosh_debug(c2s_t c2s, const char* fmt, ...)
{
    char destbuf[1024];

    va_list arg;

    va_start(arg, fmt);
    vsnprintf(destbuf, sizeof(destbuf), fmt, arg);
    va_end(arg);

    log_write(c2s->log, LOG_NOTICE, destbuf);

    return;
}


static int _s_sprintf(char* destbuf, int bufsize, const char* fmt, ...)
{
    int len;
    va_list arg;

    va_start(arg, fmt);
    len = vsnprintf(destbuf, bufsize, fmt, arg);
    va_end(arg);

    if(len >= bufsize)
        return -1;
    return len;

}


static void _c2s_bosh_session_term(sess_t sess, char* termmsg)
{

    bres_t bres;
    char argbuf[256];


    if(sess->bosh->term == 1)
        return; /* Term has been already called. Prevent twice calling */

    /* This will marks this session as terminating.*/
    sess->bosh->term = 1;


    if(sess->bosh->sendbuf != NULL)
    {	//Reset the buffer. Don't care for remaining data.
        free(sess->bosh->sendbuf);
        sess->bosh->sendbuf = NULL;
    }
    sess->bosh->sendcursize = 0;

    if(termmsg != NULL)
    {
        if(termmsg[0] == 0)
            _c2s_bosh_write_data(sess, "type=\'terminate\'", 17, 0, 0);
        else
        {
            _s_sprintf(argbuf, sizeof(argbuf), "type=\'terminate\' condition=\'%s\'", termmsg, 0);
            _c2s_bosh_write_data(sess, argbuf, strlen(argbuf), 0, 0);
        }
    }

    /* killing him */
    if(sess->active)
        for(bres = sess->resources; bres != NULL; bres = bres->next)
            sm_end(sess, bres);

    sess->bosh->rid = 0;

    xhash_zap(sess->c2s->sessions, sess->skey);

    jqueue_push(sess->c2s->dead, (void *) sess->s, 0);
    jqueue_push(sess->c2s->dead_sess, (void *) sess, 0);
}

static void _c2s_bosh_socket_close(bosh_socket_t bosh_sock)
{

        if(bosh_sock == NULL)
            return;

        if(bosh_sock->sess != NULL)
        {
            if(bosh_sock == bosh_sock->sess->bosh->connection1)
            {
                print_bosh_debug(bosh_sock->c2s, "In Sess: %p BOSH Socket1 Delete: %p\n", bosh_sock->sess, bosh_sock->sess->bosh->connection1);
                bosh_sock->sess->bosh->connection1 = NULL;
            }

            if(bosh_sock == bosh_sock->sess->bosh->connection2)
            {
                print_bosh_debug(bosh_sock->c2s, "In Sess: %p BOSH Socket2 Delete:  %p\n", bosh_sock->sess, bosh_sock->sess->bosh->connection2);
                bosh_sock->sess->bosh->connection2 = NULL;
            }

            if(bosh_sock->sess->bosh->connection1 == NULL && bosh_sock->sess->bosh->connection2 == NULL)
            {
                /* Client has no more open connections. We have to set the timeout to notice when he goes inactive! */
                bosh_sock->sess->bosh->inactivitypoint = time(NULL) + BOSH_MAXINACTIVITYTIME;
            }

        }else{
                print_bosh_debug(bosh_sock->c2s, "No BOSH Socket deleted\n");
        }
#ifdef HAVE_SSL
        _c2s_bosh_ssl_free_for_client(bosh_sock);
#endif
        _sx_buffer_clear(&bosh_sock->read_buf);
        _sx_buffer_clear(&bosh_sock->write_buf);

        print_bosh_debug(bosh_sock->c2s, "Free BOSH Socket: %p\n", bosh_sock);
        free(bosh_sock);
}

/*
    This functions job is to see if the timeout specified in the "wait"-value is near to exceed.
    In this case we have to send the empty response.
    The other job is to find and kill dead sessions.
*/


static void _c2s_client_bosh_session_walker(const char* sid, int sidlen, void* xhash_arg, void* walker_arg)
{
    sess_t sess = (sess_t)xhash_arg;
    time_t realtime = (time_t)walker_arg;
    bosh_socket_t bosh_sock1;
    bosh_socket_t bosh_sock2;

    //If not a BOSH session
    if(sess->bosh == NULL)
        return;

    if(sess->bosh->inactivitypoint != 0 && sess->bosh->inactivitypoint < realtime)
    {
        print_bosh_debug(sess->c2s, "Closing session: %s %p due to inactivity\n", sess->skey, sess);
        _c2s_bosh_session_term(sess, "Inactivity");
        return;
    }

    bosh_sock1 = sess->bosh->connection1;
    bosh_sock2 = sess->bosh->connection2;

    if(bosh_sock1 != NULL && bosh_sock1->waitpoint != 0 && bosh_sock1->waitpoint - BOSH_MINWAIT - BOSH_WAITMARGIN < realtime)
    {
        if(_c2s_bosh_queue_data(sess, NULL, 0, 1, 0) >= 0)
            mio_write(sess->c2s->mio, bosh_sock1->fd);
        print_bosh_debug(sess->c2s, "Sending keep alive response for sess %s in connection1.\n", sess->skey);
    }

    if(bosh_sock2 != NULL && bosh_sock2->waitpoint != 0 && bosh_sock2->waitpoint - BOSH_MINWAIT - BOSH_WAITMARGIN < realtime)
    {
        if(_c2s_bosh_queue_data(sess, NULL, 0, 1, 0) >= 0)
            mio_write(sess->c2s->mio, bosh_sock2->fd);
        print_bosh_debug(sess->c2s, "Sending keep alive response for sess %s in connection2.\n", sess->skey );
    }

}




static sess_t _c2s_bosh_get_session_for_client(bosh_socket_t presess, char* sid)
{
        sess_t sess;

        sess = (sess_t)xhash_get(presess->c2s->sessions, sid);
        if(sess != NULL)
        {
            log_debug(ZONE, "Found session for client. Will continue session for client with sid: %s\n", sid);
        }
        return sess;
}

static sess_t _c2s_bosh_create_session_for_client(bosh_socket_t bosh_sock, unsigned int rid)
{
        sess_t sess;
        int i;
        int flags = 0;

        /*This client seems to have no session yet. We assume he is a new client and needs an session.*/
        sess = (sess_t) calloc(1, sizeof(struct sess_st));
        if(sess == NULL)
            return NULL;

        /* This is a allocated block of memory as we are serving a bosh client */
        sess->bosh = (bosh_sess_t) calloc(1, sizeof(struct bosh_sess_st));
        if(sess->bosh == NULL)
        {
            free(sess);
            return NULL;
        }

        sess->c2s = bosh_sock->c2s;
        sess->ip = strdup(bosh_sock->ip);
        sess->port = 0;

        sess->last_activity = time(NULL);
        sess->s = sx_new(sess->c2s->sx_env, bosh_sock->fd->fd, _c2s_client_bosh_sx_callback, (void *) sess);

        bosh_sock->sess = sess;
        sess->bosh->connection1 = bosh_sock;

        if(sess->c2s->stanza_size_limit != 0)
                sess->s->rbytesmax = sess->c2s->stanza_size_limit;

        if(sess->c2s->byte_rate_total != 0)
                sess->rate = rate_new(sess->c2s->byte_rate_total, sess->c2s->byte_rate_seconds, sess->c2s->byte_rate_wait);

        if(sess->c2s->stanza_rate_total != 0)
                sess->stanza_rate = rate_new(sess->c2s->stanza_rate_total, sess->c2s->stanza_rate_seconds, sess->c2s->stanza_rate_wait);

        /* give IP to SX */
        sess->s->ip = sess->ip;
        sess->s->port = 0;

        /*Create a new session key. This will be called SID in bosh*/
        for(i = 0; i < sizeof(sess->skey); i += 2)
            sprintf(&sess->skey[i], "%02x", rand() % 256);

        sess->skey[sizeof(sess->skey) -1] = 0;

        /* remember it */
        xhash_put(sess->c2s->sessions, sess->skey, (void *) sess);

        sess->bosh->rid = rid;

        flags = SX_SASL_OFFER;
#ifdef HAVE_SSL
        /* go ssl wrappermode if they're on the ssl port */

        /* Later! */
/*        if(port == sess->c2s->local_ssl_port)
            flags |= SX_SSL_WRAPPER;*/
#endif
        sx_server_init(sess->s, flags);

        log_debug(ZONE, "Creating a new session for %s with sid %s", sess->ip, sess->skey);

        bosh_sock->want_read = 1;

        return sess;
}




//This function only writes to output queue
//canreceive_sx = 1 if we can write data into the body. This is almost always the case
//writeisoptional = 1 We want only write data if new data from SX is there
static int _c2s_bosh_queue_data(sess_t sess, char* bodyattrdata, int bodyattrlen, int canreceive_sx, int writeisoptional)
{

    char buf[2048];
    char sx_buf[1024];
    char* cachebuf;
    char* cachebuf_alias;
    int len = 0;
    int bufferlen = sizeof(buf);
    int ret;

    cachebuf = buf;
    cachebuf[0] = 0;

    if(sess->bosh->sendbuf != NULL)
    {
        return 0;
    }

    if(bodyattrdata == NULL || bodyattrlen == 0)
    {
        bodyattrlen = 0;
        bodyattrdata = "";
    }

    if(canreceive_sx)
    { //Getting all remaining data from SX

        sess->bosh->sx_buf = sx_buf;

        do{

            sess->bosh->sx_buflen = 0;

            ret = sx_can_write(sess->s);

            if( sess->bosh->sx_buflen > 0)
            {
                //Do we have enought free memory to do this ?
                if(len + sess->bosh->sx_buflen > bufferlen)
                {

                    if(cachebuf == buf)
                    {
                        cachebuf_alias = realloc(NULL, len + sess->bosh->sx_buflen);

                        if(cachebuf_alias != NULL)
                            memcpy(cachebuf_alias, buf, len);

                    }else{
                        cachebuf_alias = realloc(cachebuf, len + sess->bosh->sx_buflen);

                        if(cachebuf_alias == NULL)
                            free(cachebuf);
                    }

                    if(cachebuf_alias == NULL)
                    {
                        //Drop him
                        log_debug(ZONE, "Command buffer overflow! Can not process sid: %s", sess->skey);
                        return -1;
                    }
                    cachebuf = cachebuf_alias;
                }

                memcpy(&cachebuf[len], sx_buf, sess->bosh->sx_buflen);
                len += sess->bosh->sx_buflen;
            }

        }while(ret != 0);

    }
    //nothing to write
    if(writeisoptional && len < 1)
    {
        return 0;
    }

    if(320 + 58 + len + bodyattrlen > BOSH_MAX_HTTP_CONTENTLENGTH*1024)
    {
        //Drop him
        log_debug(ZONE, "Oversize message exceeded limit of %d with length %d for: %s", BOSH_MAX_HTTP_CONTENTLENGTH*1024, 320 + 58 + len + bodyattrlen, sess->skey);
        return -1;
    }

    sess->bosh->sendbuf = malloc(320 + 58 + len + bodyattrlen);

    if(sess->bosh->sendbuf == NULL)
    {
        //Drop him
        log_debug(ZONE, "Command buffer overflow! Can not process sid: %s", sess->skey);
        return -1;
    }

    char* http_responsemask =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/xml\r\n"
        "Server: " PACKAGE_STRING "\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Content-Length: %d\r\n"
        "\r\n"
        "<body xmlns=\'http://jabber.org/protocol/httpbind\' %.*s>%.*s</body>";

    len = sprintf(sess->bosh->sendbuf, http_responsemask, 58 + len + bodyattrlen, bodyattrlen, bodyattrdata, len, cachebuf);

    if(cachebuf != buf)
        free(cachebuf);

    if(len < 100)
    {
        //Drop him
        log_debug(ZONE, "Command buffer overflow! Can not process sid: %s", sess->skey);
        return -1;
    }

    sess->bosh->sendcursize = len;

    return len;
}

static int _c2s_bosh_write_data(sess_t sess, char* bodyattrdata, int bodyattrlen, int canreceive_sx, int writeisoptional)
{
        //First find out where to write and if we have to write
        int writeable_bosh_connection = 0;
        int enterwriteattempt = 0;
        int ret;

        //We are never allowed to keep two waiting connections
        if(sess->bosh->connection1 != NULL && sess->bosh->connection1->waitpoint > 0 &&
            sess->bosh->connection2 != NULL && sess->bosh->connection2->waitpoint > 0)
        {
            writeisoptional = 0; //We have to acknowledge one connection now and hold the other until timeout.
            writeable_bosh_connection = -1; //So we can write to any connection. I use one of them. Whatever works in the end.

        }else if(sess->bosh->connection1 != NULL && sess->bosh->connection1->waitpoint > 0){
            writeable_bosh_connection = 1;
        }else if(sess->bosh->connection2 != NULL && sess->bosh->connection2->waitpoint > 0){
            writeable_bosh_connection = 2;
        }

        if(sess->bosh->sendbuf != NULL)
        {
            enterwriteattempt = 1;

        }else{
            ret = _c2s_bosh_queue_data(sess, bodyattrdata, bodyattrlen, 1, writeisoptional);

            if(ret < 0)
                return ret;
            if(ret > 0)
                enterwriteattempt = 1;
        }

        if(enterwriteattempt == 1)
        {
            if(writeable_bosh_connection == 1 && sess->bosh->connection1 != NULL)
                mio_write(sess->c2s->mio, sess->bosh->connection1->fd);

            else if(writeable_bosh_connection == 2 && sess->bosh->connection2 != NULL)
                mio_write(sess->c2s->mio, sess->bosh->connection2->fd);

            else if(writeable_bosh_connection == -1 && sess->bosh->connection1 != NULL)
                mio_write(sess->c2s->mio, sess->bosh->connection1->fd);

            else if(writeable_bosh_connection == -1 && sess->bosh->connection2 != NULL)
                mio_write(sess->c2s->mio, sess->bosh->connection2->fd);
            else
                return 0;

            return 1;
        }
        return 0;
}

static void _c2s_client_send_bosh_errorcode(bosh_socket_t bosh_sock, int error)
{

    char* errorstring;
    sx_buf_t sx_buf;

    switch(error)
    {
        case 404:
            errorstring = "Not Found";
            break;
        case 403:
            errorstring = "Forbidden";
            break;
        default:
            errorstring = "Bad Request";
            error = 400;
    }

    sx_buf = _sx_buffer_new(NULL, 2048, NULL, NULL);

    char* http_responsemask =
        "HTTP/1.1 %d %s\r\n"
        "Server: " PACKAGE_STRING "\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n";

    _s_sprintf(sx_buf->data, sx_buf->len, http_responsemask, error, errorstring);

    sx_buf->len = strlen(sx_buf->data);

    if(bosh_sock->fd == NULL)
    {
        return;
    }

    _c2s_bosh_sock_write(bosh_sock, sx_buf);
    _sx_buffer_free(sx_buf);
}


/*
The following code has been borrowed from sx/server.c:_sx_server_element_start() and sx/server.c:_sx_server_nofity_header()
*/

static int _sx_server_bosh_stream_restart(void *arg, const char *to, const char* version) {
    sx_t s = (sx_t) arg;
    int len, i, attrib_ns_begin, attrib_val_begin, r, ns;
    const char *c;
    char* errstring;
    char id[41];
    sx_buf_t buf;
    sx_error_t sxe;
    nad_t nad;

    log_debug(ZONE, "Client requested a stream-restart");

    if(s->fail) return -1;

    XML_SetElementHandler(s->expat, NULL, NULL);
    XML_SetStartNamespaceDeclHandler(s->expat, NULL);

    char* str = "<?xml version='1.0'?><stream:stream xmlns:stream=\'" uri_STREAMS "\' xmlns=\'" uri_CLIENT "\'>";

    if(XML_Parse(s->expat, str, strlen(str), 0) == 0)
    {
        /* parse error */
        errstring = (char *) XML_ErrorString(XML_GetErrorCode(s->expat));
        _sx_debug(ZONE, "XML parse error: %s; line: %d, column: %d", errstring, XML_GetCurrentLineNumber(s->expat), XML_GetCurrentColumnNumber(s->expat));

        _sx_gen_error(sxe, SX_ERR_STREAM, "Stream error", "Unknown reason");
        _sx_event(s, event_ERROR, (void *) &sxe);
        _sx_error(s, stream_err_XML_NOT_WELL_FORMED, NULL);
        s->fail = 1;
        return -1;

    }

    /* pull interesting things out of the header */
    if(to){
        if(s->req_to != NULL) free((void*)s->req_to);
        s->req_to = strdup(to);
    }
    if(version){
        if(s->req_version != NULL) free((void*)s->req_version);
        s->req_version = strdup(version);
    }

    _sx_debug(ZONE, "stream request: to %s from %s version %s", s->req_to, s->req_from, s->req_version);

    /* check version */
    if(s->req_version != NULL && strcmp(s->req_version, "1.0") != 0) {
        /* throw an error */
        _sx_gen_error(sxe, SX_ERR_STREAM, "Stream error", "Unsupported version");
        _sx_event(s, event_ERROR, (void *) &sxe);
        _sx_error(s, stream_err_UNSUPPORTED_VERSION, NULL);
        s->fail = 1;
        return -1;
    }

    /* !!! get the app to verify this stuff? */

    /* bump */
    _sx_state(s, state_STREAM_RECEIVED);

    /* response attributes */
    if(s->req_to != NULL) s->res_from = strdup(s->req_to);
    if(s->req_from != NULL) s->res_to = strdup(s->req_from);

    /* Only send 1.0 version if client has indicated a stream version - c/f XMPP 4.4.1 para 4 */
    if(s->req_version != NULL) s->res_version = strdup("1.0");

    /* stream id */
    for(i = 0; i < 40; i++) {
        r = (int) (36.0 * rand() / RAND_MAX);
        id[i] = (r >= 0 && r <= 9) ? (r + 48) : (r + 87);
    }
    id[40] = '\0';

    s->id = strdup(id);

    _sx_debug(ZONE, "stream id is %s", id);

    /* Inlining of _sx_server_notify_header start */
    _sx_debug(ZONE, "stream established");

    /* get the plugins to setup */
    if(s->env != NULL)
        for(i = 0; i < s->env->nplugins; i++)
            if(s->env->plugins[i]->stream != NULL)
                (s->env->plugins[i]->stream)(s, s->env->plugins[i]);

    /* bump us to stream if a plugin didn't do it already */
    if(s->state < state_STREAM) {
        _sx_state(s, state_STREAM);
        _sx_event(s, event_STREAM, NULL);
    }

    /* next, build the features */
    if(s->req_version != NULL && strcmp(s->req_version, "1.0") == 0) {
        _sx_debug(ZONE, "building features nad");

        nad = nad_new();

        ns = nad_add_namespace(nad, uri_STREAMS, "stream");
        nad_append_elem(nad, ns, "features", 0);

        if(s->ns != NULL)
        {
            nad_append_attr(nad, -1, "xmlns", s->ns);
        }
/********************************************************
    Stupid way to add the addional namespace attributes from plugins to stream:feature header.
    Usually they go into stream:stream tag but this is not possible to send a stream:stream tag with HTTP-Binding.
    I'm not sure if that works really here. But at least it works for the ACK-Plugin.
*********************************************************/
        buf = _sx_buffer_new(NULL, 100, NULL, NULL);
        strcpy(buf->data, "<stream:stream>");

        // plugins can mess with the header too
        if(s->env != NULL)
            for(i = 0; i < s->env->nplugins; i++)
                if(s->env->plugins[i]->header != NULL)
                    (s->env->plugins[i]->header)(s, s->env->plugins[i], buf);

        for(i = 0; i < buf->len; i++)
        {
            if(buf->data[i] == '<' || buf->data[i] == ' ')
                continue;

            if(buf->data[i] == '>')
                break;

            if(!strncmp(&buf->data[i], "stream:stream", 13))
            {
                i += 13;
                continue;
            }
            if(!strncmp(&buf->data[i], "xmlns:", 6))
            {

                i += 6;
                attrib_ns_begin = i;

                while( buf->data[i] != '=' && buf->data[i] != ' ' && i < buf->len )
                    i++;

                if((buf->data[i] != '=' && buf->data[i] != ' ') || i >= buf->len)
                    continue; //Something seems to be wrong!

                buf->data[i] = '\0'; //Null terminate this ns string
                i++;

                while((buf->data[i] == '=' || buf->data[i] == ' ') && i < buf->len )
                    i++;
                //Find opening quote of value
                if((buf->data[i] != '\'' && buf->data[i] != '\"') || i >= buf->len)
                    continue; //Something seems to be wrong! This value has no opening quote

                i++;
                attrib_val_begin = i;

                //Find closing quote of value
                while( buf->data[i] != '\'' && buf->data[i] != '\"' && i < buf->len )
                    i++;

                if((buf->data[i] != '\'' && buf->data[i] != '\"') || i >= buf->len)
                    continue; //Something seems to be wrong! This value has no closing quote

                buf->data[i] = '\0'; //Null terminate this value string
                nad_add_namespace(nad, &buf->data[attrib_val_begin], &buf->data[attrib_ns_begin]);
            }
        }
        _sx_buffer_free(buf);
/********************************************************/

        /* get the plugins to populate it */
        if(s->env != NULL)
            for(i = 0; i < s->env->nplugins; i++)
                if(s->env->plugins[i]->features != NULL)
                    (s->env->plugins[i]->features)(s, s->env->plugins[i], nad);

        /* new buffer for the nad */
        nad_print(nad, 0, &c, &len);
        buf = _sx_buffer_new(c, len, NULL, NULL);
        nad_free(nad);
        /* send this off too */
        /* !!! should this go via wnad/rnad? */
        jqueue_push(s->wbufq, buf, 0);
        s->want_write = 1;
    }
    /* if they sent packets before the stream was established, process the now */
    if(jqueue_size(s->rnadq) > 0 && (s->state == state_STREAM || s->state == state_OPEN)) {
        _sx_debug(ZONE, "processing packets sent before stream, naughty them");
        _sx_process_read(s, _sx_buffer_new(c, 0, NULL, NULL));
    }

    /* Inlining of _sx_server_notify_header end */

    s->depth++;

    /* we're alive */
    XML_SetElementHandler(s->expat, (void *) _sx_element_start, (void *) _sx_element_end);
    XML_SetCharacterDataHandler(s->expat, (void *) _sx_cdata);
    XML_SetStartNamespaceDeclHandler(s->expat, (void *) _sx_namespace_start);

    if(s->want_write)
        _sx_event(s, event_WANT_WRITE, NULL);

    return s->want_read;
}



/** we can read */
static int _sx_bosh_read(sx_t s, char* in_buf, int read) {
    sx_buf_t out;
    int ret;

    assert((int) (s != NULL));

    /* do we care? */
    if(!s->want_read && s->state < state_CLOSING)
        return 0;           /* no more thanks */

    _sx_debug(ZONE, "%d ready for reading", s->tag);

    /* bail if something went wrong */
    if(read < 0) {
        s->want_read = 0;
        s->want_write = 0;
        return 0;
    }

    if(read == 0) {
        /* nothing to read
         * should never happen because we did get a read event,
         * thus there is something to read, or error handled
         * via (read < 0) block before (errors return -1) */
        _sx_debug(ZONE, "decoded 0 bytes read data - this should not happen");

    } else {
        _sx_debug(ZONE, "passed %d read bytes", read);

        /* make a copy for processing */
        out = _sx_buffer_new(in_buf, read, NULL, NULL);
        /* run it by the plugins */
        ret = _sx_chain_io_read(s, out);
        if(ret <= 0) {
            if(ret < 0) {
                /* permanent failure, its all over */
                /* !!! shut down */
                s->want_read = s->want_write = 0;
            }

            _sx_buffer_free(out);

            /* done */
            if(s->want_write) _sx_event(s, event_WANT_WRITE, NULL);
            return s->want_read;
        }

        _sx_debug(ZONE, "decoded read data (%d bytes): %.*s", out->len, out->len, out->data);

        /* into the parser with you */
        _sx_process_read(s, out);
    }

    /* if we've written everything, and we're closed, then inform the app it can kill us */
    if(s->want_write == 0 && s->state == state_CLOSING) {
        _sx_state(s, state_CLOSED);
        _sx_event(s, event_CLOSED, NULL);
        return 0;
    }

    if(s->state == state_CLOSED)
        return 0;

    if(s->want_write) _sx_event(s, event_WANT_WRITE, NULL);
    return s->want_read;
}



static void c2s_bosh_dummy_sx_event(sx_t a, sx_event_t b, void* c, void* d)
{

}


#ifdef HAVE_SSL

static struct _sx_st bosh_ssl_sx_mem;


sx_plugin_t c2s_bosh_init_ssl_sx_once(c2s_t c2s, ...)
{
    static void* plugin_data_ptr;
    static struct _sx_plugin_st plugin_init;
    int ret;
    va_list args;

    sx_t ssl_sx = &bosh_ssl_sx_mem;

    ssl_sx->env = c2s->sx_env;
    ssl_sx->cb = (sx_callback_t)c2s_bosh_dummy_sx_event;
    ssl_sx->cb_arg = NULL;
    ssl_sx->tag = -8888;
    ssl_sx->ssf = 0;

    ssl_sx->plugin_data = &plugin_data_ptr;
    ssl_sx->flags = SX_SSL_WRAPPER;
    ssl_sx->req_to = NULL;
    ssl_sx->type = type_SERVER;

    plugin_init.index = 0;

    va_start(args, c2s);
    ret = sx_ssl_init(ssl_sx->env, &plugin_init, args);
    va_end(args);

    if(ret != 0) {
        ssl_sx->flags = 0;
        return NULL;
    }

    return &plugin_init;
}

static void _c2s_bosh_ssl_init_for_client(bosh_socket_t bosh_sock)
{

    sx_t ssl_sx = &bosh_ssl_sx_mem;

    if(ssl_sx->flags & SX_SSL_WRAPPER)
    {

        ssl_sx->plugin_data[0] = NULL;
        ssl_sx->ssf = 0;
        /* Prevent calls to sx_error() from the SSL plugin as this makes a lot trouble */
        ssl_sx->state = state_NONE;

        bosh_sock->c2s->sx_bosh_ssl[0].server(ssl_sx, bosh_sock->c2s->sx_bosh_ssl);

        //Destroy the useless sx_chain as soon as it got created
        if(ssl_sx->wio != NULL)
        {
            free(ssl_sx->wio);
            ssl_sx->wio = NULL;
            ssl_sx->rio = NULL;
        }
        bosh_sock->ssl_conn_data = ssl_sx->plugin_data[0];
    }
}

static void _c2s_bosh_ssl_free_for_client(bosh_socket_t bosh_sock)
{
    sx_t ssl_sx = &bosh_ssl_sx_mem;

    if(ssl_sx->flags & SX_SSL_WRAPPER)
    {
        ssl_sx->plugin_data[0] = bosh_sock->ssl_conn_data;

        bosh_sock->c2s->sx_bosh_ssl->free(ssl_sx, bosh_sock->c2s->sx_bosh_ssl);
    }
}

#endif

#define BOSH_DEFAULT_BUFFER_LEN 1400


static int _c2s_bosh_sock_read(bosh_socket_t bosh_sock)
{
    sx_buf_t sx_buf;

    int len;
    sx_buf = _sx_buffer_new(NULL, BOSH_DEFAULT_BUFFER_LEN, NULL, NULL);

    if(!sx_buf)
        return -1;

    log_debug(ZONE, "reading from %d", bosh_sock->fd->fd);

    sx_buf->len = 0;

    do{
            /* do the read */
            len = recv(bosh_sock->fd->fd, &sx_buf->data[sx_buf->len], BOSH_DEFAULT_BUFFER_LEN, 0);

            if(len < 0) {

                if(!MIO_WOULDBLOCK)
                {
                    return -1;
                }

            } else if(len == 0) {
                /* they went away */
                /* We have to free something! */
                return -1;

            }else{
                sx_buf->len += len;
                _sx_buffer_alloc_margin(sx_buf, 0, BOSH_DEFAULT_BUFFER_LEN);
            }

    }while(len > 0);

#ifdef HAVE_SSL

    int ret;
    sx_t ssl_sx;
    ssl_sx = &bosh_ssl_sx_mem;

    if(ssl_sx->flags & SX_SSL_WRAPPER)
    {
        ssl_sx->plugin_data[0] = bosh_sock->ssl_conn_data;
        ssl_sx->want_read = 0;
        ssl_sx->want_write = 0;
        ssl_sx->ssf = bosh_sock->ssf;
        /* Prevent calls to sx_error() from the SSL plugin as this makes a lot trouble */
        ssl_sx->state = state_NONE;
        /* Do the sx_ssl_rio() */
        ret = bosh_sock->c2s->sx_bosh_ssl->rio(ssl_sx, bosh_sock->c2s->sx_bosh_ssl, sx_buf);

        bosh_sock->ssf = ssl_sx->ssf;

        if(ret < 0)
        {   /* There is an fatal error */
            _sx_buffer_free(sx_buf);
            return -1;
        }

        if(!bosh_sock->want_read)
            bosh_sock->want_read = ssl_sx->want_read;
        if(!bosh_sock->want_write)
            bosh_sock->want_write = ssl_sx->want_write;

    }
#endif

    _sx_buffer_alloc_margin(&bosh_sock->read_buf, 0, sx_buf->len);

    memcpy(&bosh_sock->read_buf.data[bosh_sock->read_buf.len], sx_buf->data, sx_buf->len);
    bosh_sock->read_buf.len += sx_buf->len;

    _sx_buffer_free(sx_buf);

    //There is some data to process
    if(bosh_sock->read_buf.len > 0)
        return 1;

    //There is no data to process
    return 0;
}


static int _c2s_bosh_sock_write(bosh_socket_t bosh_sock, sx_buf_t sx_buf)
{
    int len;
    int realtime;

#ifdef HAVE_SSL
    int ret;
    sx_t ssl_sx;

    ssl_sx = &bosh_ssl_sx_mem;

    if(ssl_sx->flags & SX_SSL_WRAPPER)
    {
        ssl_sx->plugin_data[0] = bosh_sock->ssl_conn_data;
        ssl_sx->want_read = 0;
        ssl_sx->want_write = 0;
        ssl_sx->ssf = bosh_sock->ssf;
        /* Prevent calls to sx_error() from the SSL plugin as this makes a lot trouble */
        ssl_sx->state = state_NONE;

        /* Do the sx_ssl_wio() */
        ret = bosh_sock->c2s->sx_bosh_ssl->wio(ssl_sx, bosh_sock->c2s->sx_bosh_ssl, sx_buf);

        bosh_sock->ssf = ssl_sx->ssf;

        if(!bosh_sock->want_read)
            bosh_sock->want_read = ssl_sx->want_read;

        if(ret < 0)
        {   /* There is an fatal error */
                return -1;
        }
    }
#endif

    if(sx_buf->len > 0)
    {   /* We have something to write */
        _sx_buffer_alloc_margin(&bosh_sock->write_buf, 0, sx_buf->len);

        memcpy(&bosh_sock->write_buf.data[bosh_sock->write_buf.len], sx_buf->data, sx_buf->len);
        bosh_sock->write_buf.len += sx_buf->len;

    }


    if(bosh_sock->write_buf.len == 0)
        /* We have nothing to write */
        return 0;


    do{
            /* do the writing */
            len = send(bosh_sock->fd->fd, bosh_sock->write_buf.data, bosh_sock->write_buf.len, 0);

            log_debug(ZONE, "%d bytes written from send-buffer", len);

            if(len < 0) {

                if(!MIO_WOULDBLOCK)
                {
                    return -1;
                }
                break;

            } else if(len == 0) {
                /* Same as MIO_WOULDBLOCK*/
                break;

            }else{

                bosh_sock->write_buf.data += len;
                bosh_sock->write_buf.len -= len;
            }

    }while(len > 0 && bosh_sock->write_buf.len > 0);

    if(bosh_sock->write_buf.len == 0)
    {
        realtime = time(NULL);
        _sx_buffer_clear(&bosh_sock->write_buf);
        bosh_sock->want_write = 0; //Because we can only send one messsage per request

        if(bosh_sock->sess != NULL)
        {
            bosh_sock->sess->bosh->inactivitypoint = realtime + BOSH_MAXINACTIVITYTIME;
        }
        bosh_sock->waitpoint = 0; //We aren't allowed to send any more
        return 0;

    }else{

        bosh_sock->want_write = 1;
        //Because we have not yet completed this messsage transfer
        return 1;
    }

}

static int c2s_bosh_parse_http_header(sx_buf_t buf)
{
    int i, k, contentlength, headerend;

    if(buf->len < 4)
        return 0;

    /* Is the header complete ?*/
    for(i = 0; i+3 < buf->len; i++)
    {
        if(buf->data[i] == '\r' && buf->data[i+1] == '\n' &&
           buf->data[i+2] == '\r' && buf->data[i+3] == '\n' )
        {

                headerend = i+4;

                if (buf->len >= 15 && strncmp("POST /http-bind ", buf->data, 15) == 0)
                {

                    //Parse the Content-Length out of the body
                    //\r\nContent-Length:  --> Length has to be 17 + 2*"\r\n" or greater
                    for(i = 15; i + 21 < buf->len; i++)
                    {
                        if(buf->data[i] == '\r' && buf->data[i+1] == '\n')
                        {
                            i += 2;

                            if(strncmp(&buf->data[i], "Content-Length:", 15) == 0)
                            {
                                i += 15;

                                while(buf->data[i] == ' ' && i+4 < buf->len)
                                    i++;
                                //k is the beginning of our wanted number as string
                                k = i;

                                while(buf->data[i] != '\r' && i+2 < buf->len)
                                    i++;

                                //Check for faulty packet
                                if(i+2 > buf->len)
                                {
                                    /* Invalid Packet */
                                    return -1;
                                }
                                //Null terminate the nummeric length string
                                buf->data[i] = '\0';

                                contentlength = atoi(&buf->data[k]);
                                buf->data += headerend;
                                buf->len -= headerend;
                                return contentlength;
                            }
                        }
                    }
                }
                if(buf->len >= 3 && strncmp("GET", buf->data, 3) == 0)
                {
                    /* HTTP Get packet. We don't want this. */
                    buf->data += headerend;
                    buf->len -= headerend;
                    return -2;
                }
                if(buf->len >= 7 && strncmp("OPTIONS ", buf->data, 7) == 0)
                {
                    /* HTTP OPTIONS packet. We have to send them the options: GET POST OPTIONS. */
                    buf->data += headerend;
                    buf->len -= headerend;
                    return -3;
                }
                return -1;
        }
    }
    return 0;
}







static void c2s_bosh_send_get_error(bosh_socket_t bosh_sock)
{

        sx_buf_t buf;
        int len;
        char* http =
        "HTTP/1.0 200 OK\r\n"
        "Content-Length: 285\r\n"
        "Server: " PACKAGE_STRING "\r\n"
        "Last-Modified: Mon, 30 Sep 2013 10:10:10 GMT\r\n"
        "Date: Mon, 30 Sep 2013 10:10:10 GMT\r\n"
        "Pragma: no-cache\r\n"
        "Cache-control: private\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n\r\n"
        "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0 Transitional//EN\">\r\n"
        "<html>\r\n"
        "  <head>\r\n"
        "    <title>JabberD2 BOSH</title>\r\n"
        "  </head>\r\n"
        "  <body bgcolor=\"#FFFFFF\">\r\n"
        "      A <a href='http://www.xmpp.org/extensions/xep-0124.html'>XEP-0124</a> - BOSH - component of Jabberd2.\r\n"
        "  </body>\r\n"
        "</html>\r\n";

        len = strlen(http);
        log_write(bosh_sock->c2s->log, LOG_NOTICE, "HTTP GET request");
        buf = _sx_buffer_new(http, len, NULL, NULL);

        /* send HTTP answer */
        _c2s_bosh_sock_write(bosh_sock, buf);
        _sx_buffer_free(buf);
}

static void c2s_bosh_send_optionheader(bosh_socket_t bosh_sock)
{

        sx_buf_t buf;
        int len;
        char* http =
        "HTTP/1.1 200 OK\r\n"
        "Server: " PACKAGE_STRING "\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Access-Control-Max-Age: 86400\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 0\r\n"
        "\r\n";

        len = strlen(http);
        log_write(bosh_sock->c2s->log, LOG_NOTICE, "HTTP OPTIONS request");
        buf = _sx_buffer_new(http, len, NULL, NULL);

        /* send HTTP answer */
        _c2s_bosh_sock_write(bosh_sock, buf);
        _sx_buffer_free(buf);
}


static int c2s_bosh_read_http_header(bosh_socket_t bosh_sock)
{
    int ret;

    ret = c2s_bosh_parse_http_header(&bosh_sock->read_buf);
    if(ret == 0)
        /* Incomplete header. We have to read more. */
        return 0;

    if(ret == -2)
    {
        /* Get header. We can not deal with that */
        c2s_bosh_send_get_error(bosh_sock);
        return -1;
    }

    if(ret == -3)
    {   /* OPTIONS header. Send him the options */
        c2s_bosh_send_optionheader(bosh_sock);
        return 0;
    }

    if(ret == -1){
        /* Invalid Packet */
        return -1;
    }

    bosh_sock->http_contentlength = ret;

    return 1;

}


static nad_t c2s_bosh_get_body_header(bosh_socket_t bosh_sock)
{

        int i;
        nad_t nad;
        char parsebuffer[2048];

        /* Check if we have a valid body */
        /* Find the length of the body. Also has it content ? */
        for(i = 1; i < bosh_sock->http_contentlength; i++)
        {
                if(bosh_sock->read_buf.data[i] == '>')
                {
                    if(bosh_sock->read_buf.data[i -1] == '/')
                    {
                            i++;
                            /* Parsing the body-tag */
                            nad = nad_parse(bosh_sock->read_buf.data, i);
                            bosh_sock->read_buf.data += i;
                            bosh_sock->read_buf.len -= i;

                            /* Also shrink the http_contentlength value to the remaining amount of data*/
                            bosh_sock->http_contentlength -= i;
                            if(bosh_sock->http_contentlength < 0 || bosh_sock->read_buf.len < 0 || bosh_sock->read_buf.len < bosh_sock->http_contentlength)
                            {
                            /* Catch it just in case I have made a mistake */
                                log_write(bosh_sock->c2s->log, LOG_ERR, "Software Error in c2s_bosh_get_body_header #1: Invalid end of packet. End of read contentlength: %d end of read buf: %d\n", bosh_sock->http_contentlength, bosh_sock->read_buf.len);
                                nad_free(nad);
                                return NULL;
                            }
                            return nad;

                    }else{

                            if(i+1 > sizeof(parsebuffer))
                                return NULL;

                            memcpy(parsebuffer, bosh_sock->read_buf.data, i);
                            parsebuffer[i] = '/';
                            i++;
                            parsebuffer[i] = '>';
                            //Parsing the body-tag
                            nad = nad_parse(parsebuffer, i+1);
                            bosh_sock->read_buf.data += i;
                            bosh_sock->read_buf.len -= i;

                            /* Also shrink the http_contentlength value to the remaining amount of data*/
                            bosh_sock->http_contentlength -= i;
                            if(bosh_sock->http_contentlength < 0 || bosh_sock->read_buf.len < 0 || bosh_sock->read_buf.len < bosh_sock->http_contentlength)
                            {
                            /* Catch it just in case I have made a mistake */
                                log_write(bosh_sock->c2s->log, LOG_ERR, "Software Error in c2s_bosh_get_body_header #2: Invalid end of packet. End of read contentlength: %d end of read buf: %d\n", bosh_sock->http_contentlength, bosh_sock->read_buf.len);
                                nad_free(nad);
                                return NULL;
                            }
                            return nad;
                    }
                }

        }
        return NULL;
}



static int c2s_bosh_session_startup(bosh_socket_t bosh_sock, nad_t nad)
{        /* Create a new session as this is a session creation request */

        char to[384];
        char tmp[512];
        char obuf[2048];
        char bosh_xmppclient_version[12];
        char bosh_version[12];
        int rid;
        int ret;
        sess_t sess;

        nad_get_attrval(nad, 0, -1, "to", to, sizeof(to));
        /* Check if this domain is available first */
        if(to[0] == 0 || xhash_get(bosh_sock->c2s->sm_avail, to) == NULL)
        {
            log_debug(ZONE, "Client tried to connect to domain: %s but we aren't %s. Is %s online ?", to, to, to);
            _c2s_client_send_bosh_errorcode(bosh_sock, 404);
            return -1;
        }

        if(nad_get_attrval(nad, 0, -1, "rid", tmp, sizeof(tmp)) < 0)
        {
                log_debug(ZONE, "couldn't parse rid from body of packet for BOSH");
                _c2s_client_send_bosh_errorcode(bosh_sock, 400);
                return -1;
        }
        rid = strtoul(tmp, NULL, 10);

        sess = _c2s_bosh_create_session_for_client(bosh_sock, rid);
        if(sess == NULL)
                return -1;

        nad_get_attrval(nad, 0, -1, "version", bosh_xmppclient_version, sizeof(bosh_xmppclient_version));
        nad_get_attrval(nad, 0, -1, "ver", bosh_version, sizeof(bosh_version));
        nad_get_attrval(nad, 0, -1, "wait", tmp, sizeof(tmp));

        sess->bosh->wait = atoi(tmp);

        if(sess->bosh->wait > BOSH_MAXWAIT)
            sess->bosh->wait = BOSH_MAXWAIT;

        if(sess->bosh->wait < BOSH_MINWAIT)
                sess->bosh->wait = BOSH_MINWAIT;

        if((bosh_version[0] != '1') || (bosh_version[1] != '.'))
        {
                strncpy(bosh_version, "1.6", sizeof(bosh_version));
        }else{
                int minor = atoi(&bosh_version[2]);
                if(minor > 6)
                {
                    strncpy(bosh_version, "1.6", sizeof(bosh_version));
                }
        }
        /* Do we have a secure channel ? */
        sess->s->ssf = bosh_sock->ssf;

        nad_get_attrval(nad, 0, -1, "content", tmp, sizeof(tmp));

        _sx_buffer_alloc_margin(&bosh_sock->read_buf, 0, 0);
        //Start the stream now
        ret = _sx_server_bosh_stream_restart(sess->s, to, bosh_xmppclient_version);

        if(ret < 0)
            return -1;

        //Building and sending a session creation response
        _s_sprintf(obuf, sizeof(obuf), "content=\'%s\' polling=\'15\' hold=\'1\' requests=\'2\' ver=\'%s\' from=\'%s\' sid=\'%s\' inactivity=\'%d\' wait=\'%d\' xmpp:version=\'1.0\' xmpp:restartlogic=\'true\' xmlns:xmpp=\'urn:xmpp:xbosh\'", tmp ,bosh_version, to, sess->skey, BOSH_MAXINACTIVITYTIME, sess->bosh->wait);
        //We have to set it to something so sending will not block.
        bosh_sock->waitpoint = time(NULL) + sess->bosh->wait;

        //Send out data. It should include the stream:features element
        if((_c2s_bosh_write_data(sess, obuf, strlen(obuf), 1, 0)) < 1)
            return -1;

        bosh_sock->want_read = 1;
        return 1;
}

static int c2s_bosh_process_stream_restart_request(bosh_socket_t bosh_sock, nad_t nad)
{
        sess_t sess;
        char to[512];

        nad_get_attrval(nad, 0, -1, "to", to, sizeof(to));


        /* Check if this domain is available first */
        if(to[0] == 0 || xhash_get(bosh_sock->c2s->sm_avail, to) == NULL)
        {
            log_debug(ZONE, "Client tried to connect to domain: %s but we aren't %s. Is %s online ?", to, to, to);
            _c2s_client_send_bosh_errorcode(bosh_sock, 404);
            return -1;
        }

        sess = bosh_sock->sess;

        //Unusual that the client will have now on 2nd stream start a different version. As atm. only version exists we send always 1.0
        _sx_server_bosh_stream_restart(sess->s, to, "1.0");

        bosh_sock->want_read = 1;
        return 1;
}

static int c2s_bosh_check_rid(bosh_socket_t bosh_sock, nad_t nad){

        char ridstr[24];
        int rid;

        if(nad_get_attrval(nad, 0, -1, "rid", ridstr, sizeof(ridstr)) < 0)
        {
                log_debug(ZONE, "couldn't parse rid from body of packet for BOSH");
                _c2s_client_send_bosh_errorcode(bosh_sock, 400);

                return -1;
        }
        rid = strtoul(ridstr, NULL, 10);

        /* Verify needs to be implemented soon */

        return 0;
}



static int c2s_bosh_read_payload(bosh_socket_t bosh_sock)
{

        int payloadlen;
        int ret;
        /* Find the length of the content. Search for the final </body> tag. We search from backwards for it.
        in case http_contentlength is smaller than read_buf->len this getting catched earlier */
        payloadlen = bosh_sock->http_contentlength;

        for(payloadlen-- ; payloadlen > 0; payloadlen--)
        {
            if(bosh_sock->read_buf.data[payloadlen] == '<' && !strncmp(&bosh_sock->read_buf.data[payloadlen], "</body", 6))
                break;
        }

        //If we have payload pass it to SX
        if(payloadlen <= 0)
            return 1;

        ret = _sx_bosh_read(bosh_sock->sess->s, bosh_sock->read_buf.data, payloadlen);


        if(bosh_sock->read_buf.len < 0)
            __asm__("int $3");

        if(ret > 0)
            bosh_sock->want_read = 1;


        return ret;

}



/*
return 0 = Don't have complete data yet. Can't process data.
return 1 = There is data to read.
return -1 = Fatal Error. Connection should be closed by callie.
*/

static int c2s_bosh_process_read_data(bosh_socket_t bosh_sock){

    int ret;
    nad_t nad;
    char sid[44];
    char type[64];
    char isrestart[64];
    sess_t sess;

    sid[0] = '\0';

        if(bosh_sock->http_contentlength == 0) //If this is true we have no message start and no message length
        {
            ret = c2s_bosh_read_http_header(bosh_sock);

            if(ret == 0)
                return 1;

            if(ret == -1){

                return -1;
            }
        }

        if(bosh_sock->read_buf.len < bosh_sock->http_contentlength)
        {   /* Still incomplete data */
            return 0;
        }

        log_debug(ZONE, "Attempt to read %d bytes", bosh_sock->http_contentlength);

        nad = c2s_bosh_get_body_header(bosh_sock);

        if(nad == NULL)
        {
                log_debug(ZONE, "Couldn't parse body of packet for BOSH");
                return -1;
        }

        if(nad_find_attr(nad, 0, -1, "prebind_token", NULL) >= 0 && bosh_sock->sess == NULL)
        {
            ret = c2s_bosh_prebind_startsession(bosh_sock, nad);
            nad_free(nad);
            bosh_sock->read_buf.len -= bosh_sock->http_contentlength;
            bosh_sock->read_buf.data += bosh_sock->http_contentlength;
            bosh_sock->http_contentlength = 0;
            return ret;
        }

        if(nad_get_attrval(nad, 0, -1, "sid", sid, sizeof(sid)) < 0 && bosh_sock->sess == NULL)
        {
            ret = c2s_bosh_session_startup(bosh_sock, nad);
            nad_free(nad);

            bosh_sock->read_buf.len -= bosh_sock->http_contentlength;
            bosh_sock->read_buf.data += bosh_sock->http_contentlength;
            bosh_sock->http_contentlength = 0;
            return ret;
        }

        //Get our session if possible
        sess = _c2s_bosh_get_session_for_client(bosh_sock, sid);
        if(!sess)
        {
                log_debug(ZONE, "Client tried to continue a non existent session");
                _c2s_client_send_bosh_errorcode(bosh_sock, 404);
                nad_free(nad);
                return -1;
        }

        /* Do we have a secure channel ? */
        sess->s->ssf = bosh_sock->ssf;

        //This is the timeout within we have to respond to the clients connection.
        bosh_sock->waitpoint = time(NULL) + sess->bosh->wait;

        if(c2s_bosh_check_rid(bosh_sock, nad) == -1)
        {
                nad_free(nad);
                return -1;
        }
        /*
        Update the reverse pointers to our real session struct. 
        This is needed to change paramters of the sess_st structure while only the bosh_socket_st struct is known
        */
        if(bosh_sock->sess == NULL)
        {   //This is a new socket connection but not usually also a new session

            //Let the socket connection know the session it belongs to
            bosh_sock->sess = sess;
            //The session must know about the connection-handle
            if(sess->bosh->connection1 == NULL){
                sess->bosh->connection1 = bosh_sock;
                print_bosh_debug(sess->c2s, "Write conection1 %s\n", sess->skey);
            }else if(sess->bosh->connection2 == NULL){
                sess->bosh->connection2 = bosh_sock;
                print_bosh_debug(sess->c2s, "Write conection2 %s\n", sess->skey);
            }else{ //Must not happen. Close one
                nad_free(nad);
                return -1;
            }

        }

        /* they did something */
        sess->last_activity = time(NULL);

        if(nad_get_attrval(nad, 0, -1, "restart", isrestart, sizeof(isrestart)) == 0 && !strncmp(isrestart, "true", 4))
        {
                ret = c2s_bosh_process_stream_restart_request(bosh_sock, nad);

                if(ret < 0)
                {
                    nad_free(nad);
                    return ret;
                }
        }

        /* We got a response so our client is active */
        /* Set it to a higher value but don't disable this. Otherwise a potential software error I have made could cause dead sessions which become never free */
        bosh_sock->sess->bosh->inactivitypoint = time(NULL) + BOSH_MAXINACTIVITYTIME + BOSH_MAXWAIT;

        ret = c2s_bosh_read_payload(bosh_sock);

        bosh_sock->read_buf.len -= bosh_sock->http_contentlength;
        bosh_sock->read_buf.data += bosh_sock->http_contentlength;
        bosh_sock->http_contentlength = 0;

        if(bosh_sock->read_buf.len == 0){
            _sx_buffer_clear(&bosh_sock->read_buf);
        }else{
            if(bosh_sock->sess)
                print_bosh_debug(bosh_sock->c2s, "Have more data to read: %s\n", bosh_sock->sess->skey);

            bosh_sock->want_read = 1;
        }

        if(nad_get_attrval(nad, 0, -1, "type", type, sizeof(type)) == 0 && !strncmp(type, "terminate", 9))
        {
                nad_free(nad);
                _c2s_bosh_session_term(sess, "");
                return -1;
        }
        nad_free(nad);

        if(_c2s_bosh_write_data(sess, NULL, 0, 1, 1) < 0)
        {
            return -1;
        }
        return ret; //No more to read = return 0


}

void _c2s_client_bosh_session_timeout_check(c2s_t c2s)
{
        xhash_walk(c2s->sessions, _c2s_client_bosh_session_walker, (void*)time(NULL));
}


int _c2s_client_bosh_mio_callback(mio_t m, mio_action_t a, mio_fd_t fd, void *data, void *arg) {
    bosh_socket_t bosh_sock = (bosh_socket_t) arg;
    c2s_t c2s = (c2s_t) arg;
    struct sockaddr_storage sa;
    socklen_t namelen = sizeof(sa);
    int port, nbytes, ret;
    sx_buf_t sx_buf;
    static int entered, mio_want_close;

    ret = 0;

    if(mio_want_close == 0){

      entered ++;

      switch(a) {
        case action_READ:

            if(bosh_sock->sess != NULL && bosh_sock->sess->bosh != NULL && bosh_sock->sess->bosh->term == 1)
            {
                    mio_want_close++;
                    ret = 0;
                    break;
            }

            log_debug(ZONE, "read action on fd %d", fd->fd);

            ioctl(fd->fd, FIONREAD, &nbytes);

            if(nbytes == 0) {
                mio_want_close++;
                ret = 0;
                break;
            }

            log_debug(ZONE, "reading from %d", fd->fd);

            if(_c2s_bosh_sock_read(bosh_sock) == 1)
            {
                ret = c2s_bosh_process_read_data(bosh_sock);
                if(ret < 0)
                {
                    mio_want_close++;
                    ret = 0;
                    break;

                }else if(ret > 0){
                    bosh_sock->want_read = 1;
                }

            }

            if(bosh_sock->want_write)
                mio_write(bosh_sock->c2s->mio, bosh_sock->fd);

            ret = bosh_sock->want_read; //No more to read = return 0
            break;

        case action_WRITE:

            if(bosh_sock->sess != NULL && bosh_sock->sess->bosh != NULL && bosh_sock->sess->bosh->term == 1)
            {
                    mio_want_close++;
                    ret = 0;
                    break;
            }

            log_debug(ZONE, "write action on fd %d", fd->fd);

            sx_buf = _sx_buffer_new(NULL, 0, NULL, NULL);


            if(bosh_sock->sess != NULL && bosh_sock->sess->s != NULL && bosh_sock->sess->bosh->sendbuf != NULL && bosh_sock->sess->bosh->sendcursize > 0 && bosh_sock->fd != NULL)
            {
                _sx_buffer_set(sx_buf, bosh_sock->sess->bosh->sendbuf, bosh_sock->sess->bosh->sendcursize, bosh_sock->sess->bosh->sendbuf);

                if(_c2s_bosh_sock_write(bosh_sock, sx_buf) < 0)
                {
                    mio_want_close++;
                    ret = 0;
                    break;
                }
                bosh_sock->sess->bosh->sendbuf = NULL;
                bosh_sock->sess->bosh->sendcursize = 0;

            }else{


                if(_c2s_bosh_sock_write(bosh_sock, sx_buf) < 0)
                {
                    mio_want_close++;
                    ret = 0;
                    break;
                }

            }
            _sx_buffer_free(sx_buf);

            if(bosh_sock->want_read)
                mio_read(bosh_sock->c2s->mio, bosh_sock->fd);

            ret = bosh_sock->want_write;
            break;

            //If we have no more to write: return 0

        case action_CLOSE:

            log_debug(ZONE, "close action on fd %d", fd->fd);
            _c2s_bosh_socket_close(bosh_sock);
            entered --;
            return 0;

        case action_ACCEPT:
            log_debug(ZONE, "accept action on fd %d", fd->fd);

            getpeername(fd->fd, (struct sockaddr *) &sa, &namelen);
            port = j_inet_getport(&sa);

            log_write(c2s->log, LOG_NOTICE, "[%d] [%s, port=%d] connect", fd->fd, (char *) data, port);

            if(c2s == NULL)
            {
                ret = 1;
                break;
            }

            if(_c2s_client_accept_check(c2s, fd, (char *) data) != 0)
            {
                ret = 1;
                break;
            }

            bosh_sock = (bosh_socket_t) calloc(1, sizeof(struct bosh_socket_st));

            if(bosh_sock == NULL)
            {
                log_debug(ZONE, "Out of memory! Dropping fd %d", fd->fd);
                ret = 1;
                break;
            }

            bosh_sock->c2s = c2s;

            bosh_sock->fd = fd;

            print_bosh_debug(bosh_sock->c2s, "New bosh connection ptr: %p\n", bosh_sock);

            strncpy(bosh_sock->ip, data, sizeof(bosh_sock->ip));
            bosh_sock->ip[sizeof(bosh_sock->ip) -1] = 0;

            bosh_sock->sess = NULL;

            /*Update the callback handler*/
            mio_app(m, fd, _c2s_client_bosh_mio_callback, (void *) bosh_sock );

#ifdef HAVE_SSL
            _c2s_bosh_ssl_init_for_client(bosh_sock);
#endif
            mio_read(bosh_sock->c2s->mio, bosh_sock->fd);
            break;

      }
      entered --;
    }

    if(mio_want_close > 0 && entered == 0)
    {
        mio_want_close = 0;
        mio_close(bosh_sock->c2s->mio, bosh_sock->fd);
    }
    return ret;
}

void c2s_bosh_free_session(sess_t sess)
{
        if(sess->bosh == NULL)
            return;

        //Terminate all remaining open connections
        if(sess->bosh->connection1 != NULL)
            mio_close(sess->c2s->mio, sess->bosh->connection1->fd);
        if(sess->bosh->connection2 != NULL)
            mio_close(sess->c2s->mio, sess->bosh->connection2->fd);

        if(sess->bosh->sendbuf != NULL)
            free(sess->bosh->sendbuf);

        free(sess->bosh);
        sess->bosh = NULL;
}




void c2s_bosh_prebind_bindsession(bosh_socket_t bosh_sock, const char* resource)
{
        int ns;
        sess_t sess;
        sx_buf_t wipebuf;

        /* resource bind */
        bres_t bres, ires;

        if(bosh_sock->sess == NULL)
            return;

        sess = bosh_sock->sess;

        jid_t jid = jid_new(sess->s->auth_id, -1);

        /* get the resource */
//        elem = nad_find_elem(nad, elem, ns, "resource", 1);

        /* user-specified resource */
        if(resource != NULL && resource[0] != '\0') {

            /* Put resource into JID */
            if (jid == NULL || jid_reset_components(jid, jid->node, jid->domain, resource) == NULL) {
                log_debug(ZONE, "invalid jid data");
                return;
            }

            /* check if resource already bound */
            for(bres = sess->resources; bres != NULL; bres = bres->next)
                if(strcmp(bres->jid->resource, jid->resource) == 0){

                    log_debug(ZONE, "resource /%s already bound - generating", jid->resource);
                    jid_random_part(jid, jid_RESOURCE);
                }

        } else {
            /* generate random resource */
            log_debug(ZONE, "no resource given - generating");
            jid_random_part(jid, jid_RESOURCE);
        }

        /* attach new bound jid holder */
        bres = (bres_t) calloc(1, sizeof(struct bres_st));
        bres->jid = jid;
        if(sess->resources != NULL) {
            for(ires = sess->resources; ires->next != NULL; ires = ires->next);
            ires->next = bres;
        } else
            sess->resources = bres;

        sess->bound += 1;

        log_write(sess->c2s->log, LOG_NOTICE, "[%s] bound: jid=%s", sess->skey, jid_full(bres->jid));

        /* build a result packet, we'll send this back to the client after we have a session for them */
        sess->result = nad_new();

        ns = nad_add_namespace(sess->result, uri_CLIENT, NULL);

        nad_append_elem(sess->result, ns, "iq", 0);
        nad_set_attr(sess->result, 0, -1, "type", "result", 6);

        ns = nad_add_namespace(sess->result, uri_BIND, NULL);

        nad_append_elem(sess->result, ns, "bind", 1);
        nad_append_elem(sess->result, ns, "jid", 2);
        nad_append_cdata(sess->result, jid_full(bres->jid), strlen(jid_full(bres->jid)), 3);

        /* our local id */
        strncpy(bres->c2s_id, sess->skey, sizeof(bres->c2s_id));
        bres->c2s_id[sizeof(bres->c2s_id) -1] = 0;

        /* start a session with the sm */
        sm_start(sess, bres);

        /* wipe every buffer which has data to write! */
        if(bosh_sock->sess->s->wbufpending)
        {
            _sx_buffer_free(bosh_sock->sess->s->wbufpending);
            bosh_sock->sess->s->wbufpending = NULL;
        }
        while((wipebuf = jqueue_pull(bosh_sock->sess->s->wbufq)) != NULL)
        {
            _sx_buffer_free(wipebuf);
        }

        /* handled */
        return;

}

int c2s_bosh_prebind_startsession(bosh_socket_t bosh_sock, nad_t nad)
{

    char prebind_token[64];
    char prebind_token64[40];
    char prebind_username[128];
    char prebind_resource[128];

    c2s_t c2s = bosh_sock->c2s;

    nad_get_attrval(nad, 0, -1, "prebind_token", prebind_token64, sizeof(prebind_token64));
    apr_base64_decode(prebind_token, prebind_token64, sizeof(prebind_token));

    if(strlen(prebind_token) > 16 && c2s->local_http_prebind_token != NULL && strcmp(prebind_token, c2s->local_http_prebind_token) == 0)
    {


        if(nad_get_attrval(nad, 0, -1, "prebind_username", prebind_username, sizeof(prebind_username)) != 0)
        {
            log_write(c2s->log, LOG_ERR, "Prebind request without a username");
            _c2s_client_send_bosh_errorcode(bosh_sock, 400);
            return -1;
        }

        log_write(c2s->log, LOG_NOTICE, "Processing http-prebind request for the user: %s\n", prebind_username);

        nad_get_attrval(nad, 0, -1, "prebind_resource", prebind_resource, sizeof(prebind_resource));

        /* we need user_exists(), at the very least */
        if(c2s->ar == NULL || c2s->ar->user_exists == NULL)
        {
            log_write(c2s->log, LOG_ERR, "auth module has no check for user existence");
            _c2s_client_send_bosh_errorcode(bosh_sock, 400);
            return -1;
        }
        if(c2s_bosh_session_startup(bosh_sock, nad) < 0)
        {
            _c2s_client_send_bosh_errorcode(bosh_sock, 400);
            return -1;
        }
        if(bosh_sock->sess == NULL){
            _c2s_client_send_bosh_errorcode(bosh_sock, 400);
            return -1;
        }

        /* do we have the user? */
        if((c2s->ar->user_exists)(c2s->ar, prebind_username, bosh_sock->sess->host->realm) == 0) {
            log_write(c2s->log, LOG_ERR, "Prebind request for an invalid user name");
            _c2s_client_send_bosh_errorcode(bosh_sock, 404);
            return -1;
        }

        bosh_sock->sess->sasl_authd = 1;
        bosh_sock->sess->s->auth_id = malloc(strlen(prebind_username) + strlen(bosh_sock->sess->host->realm) + 2);

        if(bosh_sock->sess->s->auth_id == NULL){

                _c2s_client_send_bosh_errorcode(bosh_sock, 400);
                return -1;
        }
        sprintf((char*)bosh_sock->sess->s->auth_id, "%s@%s", prebind_username, bosh_sock->sess->host->realm);

        c2s_bosh_prebind_bindsession(bosh_sock, prebind_resource);


    }else{
        log_write(c2s->log, LOG_NOTICE, "Http-prebind request from: %s without a valid token\n", bosh_sock->ip);
        _c2s_client_send_bosh_errorcode(bosh_sock, 403);
    }

    return -1;

}

