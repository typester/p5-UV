#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#define NEED_sv_2pvbyte
#include "ppport.h"

#include <assert.h>
#include <stdlib.h>

#include <uv.h>

typedef struct {
    SV* connection_cb;
    SV* connect_cb;
    SV* read_cb;
    SV* write_cb;
} cb_pair_t;

static void close_cb(uv_handle_t* handle) {
    cb_pair_t* pair;

    if (UV_TIMER == handle->type) {
        if (NULL != handle->data) {
            SvREFCNT_dec((SV*)handle->data);
        }
    }
    else {
        pair = (cb_pair_t*)handle->data;
        if (NULL != pair->connection_cb)
            SvREFCNT_dec(pair->connection_cb);
        if (NULL != pair->connect_cb)
            SvREFCNT_dec(pair->connect_cb);
        if (NULL != pair->read_cb)
            SvREFCNT_dec(pair->read_cb);
        if (NULL != pair->write_cb)
            SvREFCNT_dec(pair->write_cb);
        free(pair);
    }

    free(handle);
}

static void connection_cb(uv_stream_t* server, int status) {
    SV* cb;

    dSP;

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    PUTBACK;

    assert(0 == status);

    cb = ((cb_pair_t*)server->data)->connection_cb;

    call_sv(cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void connect_cb(uv_connect_t* req, int status) {
    uv_stream_t* stream = req->handle;
    SV* sv_status;
    SV* cb;

    dSP;

    ENTER;
    SAVETMPS;

    sv_status = sv_2mortal(newSViv(status));

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    cb = ((cb_pair_t*)stream->data)->connect_cb;

    call_sv(cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;

    free(req);
}

static uv_buf_t alloc_cb(uv_handle_t* handle, size_t suggested_size) {
    char* buf;

    buf = (char*)malloc(suggested_size);
    assert(buf);

    return uv_buf_init(buf, suggested_size);
}

static void read_cb(uv_stream_t* stream, ssize_t nread, uv_buf_t buf) {
    SV* cb;
    SV* sv_nread;
    SV* sv_buf;

    dSP;

    ENTER;
    SAVETMPS;

    sv_nread = sv_2mortal(newSViv(nread));
    if (nread > 0) {
        sv_buf = sv_2mortal(newSVpv(buf.base, nread));
    }
    else {
        sv_buf = sv_2mortal(newSV(0));
    }

    PUSHMARK(SP);
    XPUSHs(sv_nread);
    XPUSHs(sv_buf);
    PUTBACK;

    cb = ((cb_pair_t*)stream->data)->read_cb;

    call_sv(cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;

    free(buf.base);
}

static void write_cb(uv_write_t* req, int status){
    uv_stream_t* stream = req->handle;
    cb_pair_t* cb_pair  = (cb_pair_t*)stream->data;
    SV* sv_status;
    SV* cb;

    dSP;

    if (cb_pair->write_cb) {
        ENTER;
        SAVETMPS;

        sv_status = sv_2mortal(newSViv(status));

        PUSHMARK(SP);
        XPUSHs(sv_status);
        PUTBACK;

        cb = ((cb_pair_t*)stream->data)->write_cb;

        call_sv(cb, G_SCALAR);

        SPAGAIN;

        PUTBACK;
        FREETMPS;
        LEAVE;
    }

    free(req);
}

static void timer_cb(uv_timer_t* handle, int status) {
    SV* cb;

    dSP;

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    PUTBACK;

    assert(0 == status);

    cb = (SV*)handle->data;

    call_sv(cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

MODULE=UV PACKAGE=UV PREFIX=uv_

PROTOTYPES: DISABLE

void
uv_run()
CODE:
{
    uv_run(uv_default_loop());
}

void
uv_version()
CODE:
{
    SV* sv;

    sv = sv_2mortal(newSV(0));
    sv_setpvf(sv, "%d.%d", UV_VERSION_MAJOR, UV_VERSION_MINOR);

    ST(0) = sv;
}

int
uv_is_active(uv_handle_t* handle)

void
uv_close(uv_handle_t* handle)
CODE:
{
    uv_close(handle, close_cb);
}

int
uv_listen(uv_stream_t* stream, int backlog, SV* cb)
CODE:
{
    cb_pair_t* cb_pair = (cb_pair_t*)stream->data;

    if (cb_pair->connection_cb)
        SvREFCNT_dec(cb_pair->connection_cb);
    cb_pair->connection_cb = SvREFCNT_inc(cb);

    RETVAL = uv_listen(stream, backlog, connection_cb);
}
OUTPUT:
    RETVAL

int
uv_accept(uv_stream_t* server, uv_stream_t* client)

int
uv_read_start(uv_stream_t* stream, SV* cb)
CODE:
{
    cb_pair_t* cb_pair = (cb_pair_t*)stream->data;

    if (cb_pair->read_cb)
        SvREFCNT_dec(cb_pair->read_cb);
    cb_pair->read_cb = SvREFCNT_inc(cb);

    RETVAL = uv_read_start(stream, alloc_cb, read_cb);
}
OUTPUT:
    RETVAL

int
uv_read_stop(uv_stream_t* stream)

int
uv_write(uv_stream_t* stream, SV* sv_buf, SV* cb = NULL)
CODE:
{
    cb_pair_t* cb_pair = (cb_pair_t*)stream->data;
    char* buf;
    STRLEN len;
    uv_write_t* req;
    uv_buf_t b;

    if (cb_pair->write_cb)
        SvREFCNT_dec(cb_pair->write_cb);

    if (cb)
        cb_pair->write_cb = SvREFCNT_inc(cb);

    req = (uv_write_t*)malloc(sizeof(uv_write_t));
    assert(req);

    buf = SvPV(sv_buf, len);

    b = uv_buf_init(buf, len);

    RETVAL = uv_write(req, stream, &b, 1, write_cb);
}
OUTPUT:
    RETVAL

void
uv_tcp_init()
CODE:
{
    SV* sv_tcp;
    uv_tcp_t* tcp;
    HV* hv;
    int r;

    hv = (HV*)sv_2mortal((SV*)newHV());
    sv_tcp = sv_2mortal(newRV_inc((SV*)hv));

    sv_bless(sv_tcp, gv_stashpv("UV::tcp", 1));

    tcp = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
    assert(tcp);

    r = uv_tcp_init(uv_default_loop(), tcp);
    assert(0 == r);

    tcp->data = (void*)calloc(1, sizeof(cb_pair_t));

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)tcp;

    ST(0) = sv_tcp;
}

int
uv_tcp_nodelay(uv_tcp_t* tcp, int enable = 1)

int
uv_tcp_keepalive(uv_tcp_t* tcp, int enable, unsigned int delay)

int
uv_tcp_simultaneous_accepts(uv_tcp_t* tcp, int enable)

int
uv_tcp_bind(uv_tcp_t* tcp, const char* ip, int port)
CODE:
{
    RETVAL = uv_tcp_bind(tcp, uv_ip4_addr(ip, port));
}
OUTPUT:
    RETVAL

int
uv_tcp_bind6(uv_tcp_t* tcp, const char* ip, int port)
CODE:
{
    RETVAL = uv_tcp_bind6(tcp, uv_ip6_addr(ip, port));
}
OUTPUT:
    RETVAL

int
uv_tcp_connect(uv_tcp_t* tcp, const char* ip, int port, SV* cb)
CODE:
{
    uv_connect_t* req;
    cb_pair_t* cb_pair = (cb_pair_t*)tcp->data;

    if (cb_pair->connect_cb)
        SvREFCNT_dec(cb_pair->connect_cb);
    cb_pair->connect_cb = SvREFCNT_inc(cb);

    req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    assert(req);

    RETVAL = uv_tcp_connect(req, tcp, uv_ip4_addr(ip, port), connect_cb);
}
OUTPUT:
    RETVAL

int
uv_tcp_connect6(uv_tcp_t* tcp, const char* ip, int port, SV* cb)
CODE:
{
    uv_connect_t* req;
    cb_pair_t* cb_pair = (cb_pair_t*)tcp->data;

    if (cb_pair->connect_cb)
        SvREFCNT_dec(cb_pair->connect_cb);
    cb_pair->connect_cb = SvREFCNT_inc(cb);

    req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    assert(req);

    RETVAL = uv_tcp_connect6(req, tcp, uv_ip6_addr(ip, port), connect_cb);
}
OUTPUT:
    RETVAL

void
uv_timer_init()
CODE:
{
    SV* sv_timer;
    uv_timer_t* timer;
    HV* hv;
    int r;

    hv       = (HV*)sv_2mortal((SV*)newHV());
    sv_timer = sv_2mortal(newRV_inc((SV*)hv));

    sv_bless(sv_timer, gv_stashpv("UV::timer", 1));

    timer = (uv_timer_t*)malloc(sizeof(uv_timer_t));
    assert(timer);

    r = uv_timer_init(uv_default_loop(), timer);
    assert(0 == r);
    timer->data = NULL;

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)timer;

    ST(0) = sv_timer;
}

int
uv_timer_start(uv_timer_t* timer, double timeout, double repeat, SV* cb)
CODE:
{
    if (timer->data)
        SvREFCNT_dec((SV*)timer->data);
    timer->data = (void*)SvREFCNT_inc(cb);

    RETVAL = uv_timer_start(timer, timer_cb, (int64_t)timeout, (int64_t)repeat);
}
OUTPUT:
    RETVAL

int
uv_timer_stop(uv_timer_t* timer)

int
uv_timer_again(uv_timer_t* timer)

void
uv_timer_set_repeat(uv_timer_t* timer, double repeat)
CODE:
{
    uv_timer_set_repeat(timer, (int64_t)repeat);
}

double
uv_timer_get_repeat(uv_timer_t* timer)
CODE:
{
    RETVAL = (double)uv_timer_get_repeat(timer);
}
OUTPUT:
    RETVAL

