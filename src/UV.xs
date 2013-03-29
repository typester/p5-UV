#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#define NEED_sv_2pvbyte
#include "ppport.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#define UV_ERRNO_CONST_GEN(val, name, s) \
    newCONSTSUB(stash, #name, newSViv(val));

#define UV_CONST_GEN(uc, lc) \
    newCONSTSUB(stash, #uc, newSViv(UV_##uc));    \
    newCONSTSUB(stash, "UV_" #uc, newSViv(UV_##uc));

/* Handle wrappers */
typedef struct p5uv_handle_s p5uv_handle_t;
typedef struct p5uv_stream_s p5uv_stream_t;
typedef struct p5uv_tcp_s p5uv_tcp_t;
typedef struct p5uv_udp_s p5uv_udp_t;
typedef struct p5uv_pipe_s p5uv_pipe_t;
typedef struct p5uv_tty_s p5uv_tty_t;
typedef struct p5uv_poll_s p5uv_poll_t;
typedef struct p5uv_timer_s p5uv_timer_t;
typedef struct p5uv_prepare_s p5uv_prepare_t;
typedef struct p5uv_check_s p5uv_check_t;
typedef struct p5uv_idle_s p5uv_idle_t;
typedef struct p5uv_async_s p5uv_async_t;

#define P5UV_HANDLE_FIELDS \
    uv_handle_t* handle;   \
    SV* close_cb;

struct p5uv_handle_s {
    P5UV_HANDLE_FIELDS
};

#define P5UV_STREAM_FIELDS \
    SV* read_cb;           \
    SV* write_cb;          \
    SV* connect_cb;        \
    SV* connection_cb;     \
    SV* shutdown_cb;

struct p5uv_stream_s {
    P5UV_HANDLE_FIELDS
    P5UV_STREAM_FIELDS
};

struct p5uv_tcp_s {
    P5UV_HANDLE_FIELDS
    P5UV_STREAM_FIELDS
};

struct p5uv_udp_s {
    P5UV_HANDLE_FIELDS
    SV* send_cb;
    SV* recv_cb;
};

struct p5uv_tty_s {
    P5UV_HANDLE_FIELDS
    P5UV_STREAM_FIELDS
};

struct p5uv_pipe_s {
    P5UV_HANDLE_FIELDS
    P5UV_STREAM_FIELDS
};

struct p5uv_poll_s {
    P5UV_HANDLE_FIELDS
    SV* cb;
};

struct p5uv_prepare_s {
    P5UV_HANDLE_FIELDS
    SV* cb;
};

struct p5uv_check_s {
    P5UV_HANDLE_FIELDS
    SV* cb;
};

struct p5uv_idle_s {
    P5UV_HANDLE_FIELDS
    SV* cb;
};

struct p5uv_async_s {
    P5UV_HANDLE_FIELDS
    SV* cb;
};

struct p5uv_timer_s {
    P5UV_HANDLE_FIELDS
    SV* cb;
};

#undef P5UV_HANDLE_FIELDS
#undef P5UV_STREAM_FIELDS

static p5uv_handle_t* p5uv_handle_init(uv_handle_t* uv_handle, uv_handle_type type) {
    p5uv_handle_t* p5uv_handle;

    switch (type) {
        case UV_TCP:
            p5uv_handle = (p5uv_handle_t*)calloc(1, sizeof(p5uv_tcp_t));
            break;
        case UV_UDP:
            p5uv_handle = (p5uv_handle_t*)calloc(1, sizeof(p5uv_udp_t));
            break;
        case UV_TTY:
            p5uv_handle = (p5uv_handle_t*)calloc(1, sizeof(p5uv_tty_t));
            break;
        case UV_NAMED_PIPE:
            p5uv_handle = (p5uv_handle_t*)calloc(1, sizeof(p5uv_pipe_t));
            break;
        case UV_POLL:
            p5uv_handle = (p5uv_handle_t*)calloc(1, sizeof(p5uv_poll_t));
            break;
        case UV_PREPARE:
            p5uv_handle = (p5uv_handle_t*)calloc(1, sizeof(p5uv_prepare_t));
            break;
        case UV_CHECK:
            p5uv_handle = (p5uv_handle_t*)calloc(1, sizeof(p5uv_check_t));
            break;
        case UV_IDLE:
            p5uv_handle = (p5uv_handle_t*)calloc(1, sizeof(p5uv_idle_t));
            break;
        case UV_ASYNC:
            p5uv_handle = (p5uv_handle_t*)calloc(1, sizeof(p5uv_async_t));
            break;
        case UV_TIMER:
            p5uv_handle = (p5uv_handle_t*)calloc(1, sizeof(p5uv_timer_t));
            break;
        default:
            croak("Unknown handle type: %d", uv_handle->type);
    }

    if (NULL == p5uv_handle) {
        croak("cannot allocate handle wrapper");
    }

    return p5uv_handle;
}

static SV* sv_handle_wrap(uv_handle_t* uv_handle) {
    SV* sv;
    HV* hv;

    hv = (HV*)sv_2mortal((SV*)newHV());
    sv = sv_2mortal(newRV_inc((SV*)hv));

    sv_bless(sv, gv_stashpv("UV::handle", 1));

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)uv_handle;

    return sv;
}

static SV* sv_handle_wrap_init(uv_handle_t* uv_handle, uv_handle_type type) {
    uv_handle->data = (void*)p5uv_handle_init(uv_handle, type);
    return sv_handle_wrap(uv_handle);
}

static void shutdown_cb(uv_shutdown_t* req, int status) {
    uv_stream_t* stream = req->handle;
    p5uv_stream_t* p5stream = (p5uv_stream_t*)stream->data;
    SV* sv_status;
    dSP;

    sv_status = sv_2mortal(newSViv(status));

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    call_sv(p5stream->shutdown_cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;

    free(req);
}

static void close_cb(uv_handle_t* handle) {
    p5uv_handle_t* p5handle;
    p5uv_stream_t* p5stream;
    p5uv_udp_t* p5udp;
    p5uv_poll_t* p5poll;
    dSP;

    p5handle = (p5uv_handle_t*)handle->data;

    if (p5handle->close_cb) {
        ENTER;
        SAVETMPS;

        PUSHMARK(SP);
        PUTBACK;

        call_sv(p5handle->close_cb, G_SCALAR);

        SPAGAIN;

        PUTBACK;
        FREETMPS;
        LEAVE;

        SvREFCNT_dec(p5handle->close_cb);
    }

    switch (handle->type) {
        case UV_TCP:
        case UV_TTY:
        case UV_NAMED_PIPE:
            /* stream */
            p5stream = (p5uv_stream_t*)p5handle;
            if (NULL != p5stream->read_cb)
                SvREFCNT_dec(p5stream->read_cb);
            if (NULL != p5stream->write_cb)
                SvREFCNT_dec(p5stream->write_cb);
            if (NULL != p5stream->connect_cb)
                SvREFCNT_dec(p5stream->connect_cb);
            if (NULL != p5stream->connection_cb)
                SvREFCNT_dec(p5stream->connection_cb);
            if (NULL != p5stream->shutdown_cb)
                SvREFCNT_dec(p5stream->shutdown_cb);
            break;

        case UV_UDP:
            p5udp = (p5uv_udp_t*)p5handle;
            if (NULL != p5udp->send_cb)
                SvREFCNT_dec(p5udp->send_cb);
            if (NULL != p5udp->recv_cb)
                SvREFCNT_dec(p5udp->recv_cb);
            break;

        case UV_POLL:
        case UV_PREPARE:
        case UV_CHECK:
        case UV_IDLE:
        case UV_ASYNC:
        case UV_TIMER:
            /* simple cb handles */
            p5poll = (p5uv_poll_t*)p5handle;
            if (NULL != p5poll->cb)
                SvREFCNT_dec(p5poll->cb);
            break;

        default:
            croak("unknown handle type: %d", handle->type);
    }

    free(handle);
    Safefree(p5handle);
}

static void poll_cb(uv_poll_t* handle, int status, int events) {
    SV* sv_status;
    SV* sv_events;
    p5uv_poll_t* p5poll = (p5uv_poll_t*)handle->data;

    dSP;

    ENTER;
    SAVETMPS;

    sv_status = sv_2mortal(newSViv(status));
    sv_events = sv_2mortal(newSViv(events));

    PUSHMARK(SP);
    XPUSHs(sv_status);
    XPUSHs(sv_events);
    PUTBACK;

    call_sv(p5poll->cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void connection_cb(uv_stream_t* server, int status) {
    p5uv_stream_t* p5stream = (p5uv_stream_t*)server->data;

    dSP;

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    PUTBACK;

    assert(0 == status);

    call_sv(p5stream->connection_cb, G_SCALAR);

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

    cb = ((p5uv_stream_t*)stream->data)->connect_cb;

    call_sv(cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;

    Safefree(req);
}

static uv_buf_t alloc_cb(uv_handle_t* handle, size_t suggested_size) {
    char* buf;

    PERL_UNUSED_ARG(handle);

    buf = (char*)malloc(suggested_size);
    if (NULL == buf) {
        croak("cannot allocate buffer");
    }

    return uv_buf_init(buf, suggested_size);
}

static void read_cb(uv_stream_t* stream, ssize_t nread, uv_buf_t buf) {
    SV* sv_nread;
    SV* sv_buf;
    p5uv_stream_t* p5stream = (p5uv_stream_t*)stream->data;

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

    call_sv(p5stream->read_cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;

    free(buf.base);
}

static void read2_cb(uv_pipe_t* pipe, ssize_t nread, uv_buf_t buf, uv_handle_type pending) {
    SV* sv_nread;
    SV* sv_buf;
    SV* sv_pending;
    p5uv_stream_t* p5stream = (p5uv_stream_t*)pipe->data;

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
    sv_pending = sv_2mortal(newSViv(pending));

    PUSHMARK(SP);
    XPUSHs(sv_nread);
    XPUSHs(sv_buf);
    XPUSHs(sv_pending);
    PUTBACK;

    call_sv(p5stream->read_cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;

    free(buf.base);
}

static void write_cb(uv_write_t* req, int status){
    uv_stream_t* stream = req->handle;
    p5uv_stream_t* p5stream = (p5uv_stream_t*)stream->data;
    SV* sv_status;

    dSP;

    if (p5stream->write_cb) {
        ENTER;
        SAVETMPS;

        sv_status = sv_2mortal(newSViv(status));

        PUSHMARK(SP);
        XPUSHs(sv_status);
        PUTBACK;

        call_sv(p5stream->write_cb, G_SCALAR);

        SPAGAIN;

        PUTBACK;
        FREETMPS;
        LEAVE;
    }

    Safefree(req);
}

static void send_cb(uv_udp_send_t* req, int status) {
    uv_udp_t* udp     = req->handle;
    p5uv_udp_t* p5udp = (p5uv_udp_t*)udp->data;
    SV* sv_status;
    dSP;

    if (p5udp->send_cb) {
        ENTER;
        SAVETMPS;

        sv_status = sv_2mortal(newSViv(status));

        PUSHMARK(SP);
        XPUSHs(sv_status);
        PUTBACK;

        call_sv(p5udp->send_cb, G_SCALAR);

        SPAGAIN;

        PUTBACK;
        FREETMPS;
        LEAVE;
    }

    Safefree(req);
}

static void recv_cb(uv_udp_t* handle, ssize_t nread, uv_buf_t buf,
    struct sockaddr* addr, unsigned flags) {

    SV* sv_nread;
    SV* sv_buf;
    SV* sv_host;
    SV* sv_port;
    SV* sv_flags;
    struct sockaddr_in* addrin;
    struct sockaddr_in6* addrin6;
    char ip[INET6_ADDRSTRLEN];
    p5uv_udp_t* p5udp = (p5uv_udp_t*)handle->data;
    dSP;

    ENTER;
    SAVETMPS;

    sv_nread = sv_2mortal(newSViv(nread));
    sv_flags = sv_2mortal(newSViv(flags));
    if (nread > 0) {
        sv_buf = sv_2mortal(newSVpv(buf.base, nread));
    }
    else {
        sv_buf = sv_2mortal(newSV(0));
    }

    if (NULL != addr) {
        switch (addr->sa_family) {
            case AF_INET:
                addrin = (struct sockaddr_in*)addr;
                uv_inet_ntop(AF_INET, &addrin->sin_addr, ip, INET6_ADDRSTRLEN);
                sv_host = sv_2mortal(newSV(0));
                sv_setpv(sv_host, ip);
                sv_port = sv_2mortal(newSViv(ntohs(addrin->sin_port)));
                break;

            case AF_INET6:
                addrin6 = (struct sockaddr_in6*)addr;
                uv_inet_ntop(AF_INET6, &addrin6->sin6_addr, ip, INET6_ADDRSTRLEN);
                sv_host = sv_2mortal(newSV(0));
                sv_setpv(sv_host, ip);
                sv_port = sv_2mortal(newSViv(ntohs(addrin6->sin6_port)));
                break;

            default:
                assert(0 && "bad address family");
                abort();
        }
    }
    else {
        sv_host = sv_2mortal(newSV(0));
        sv_port = sv_2mortal(newSV(0));
    }

    PUSHMARK(SP);
    XPUSHs(sv_nread);
    XPUSHs(sv_buf);
    XPUSHs(sv_host);
    XPUSHs(sv_port);
    XPUSHs(sv_flags);
    PUTBACK;

    call_sv(p5udp->recv_cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;

    free(buf.base);
}

static void prepare_cb(uv_prepare_t* handle, int status) {
    SV* sv_status;
    p5uv_prepare_t* p5prepare = (p5uv_prepare_t*)handle->data;
    dSP;

    sv_status = sv_2mortal(newSViv(status));

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    call_sv(p5prepare->cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void check_cb(uv_check_t* handle, int status) {
    SV* sv_status;
    p5uv_check_t* p5check = (p5uv_check_t*)handle->data;
    dSP;

    sv_status = sv_2mortal(newSViv(status));

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    call_sv(p5check->cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void idle_cb(uv_idle_t* handle, int status) {
    SV* sv_status;
    p5uv_idle_t* p5idle = (p5uv_idle_t*)handle->data;

    dSP;

    ENTER;
    SAVETMPS;

    sv_status = sv_2mortal(newSViv(status));

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    call_sv(p5idle->cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void async_cb(uv_async_t* handle, int status) {
    SV* sv_status;
    p5uv_async_t* p5async = (p5uv_async_t*)handle->data;

    dSP;

    ENTER;
    SAVETMPS;

    sv_status = sv_2mortal(newSViv(status));

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    call_sv(p5async->cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void timer_cb(uv_timer_t* handle, int status) {
    SV* sv_status;
    p5uv_timer_t* p5timer = (p5uv_timer_t*)handle->data;

    dSP;

    ENTER;
    SAVETMPS;

    sv_status = sv_2mortal(newSViv(status));

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    call_sv(p5timer->cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void walk_cb(uv_handle_t* handle, void* arg) {
    SV* sv_handle = sv_handle_wrap(handle);

    dSP;

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_handle);
    PUTBACK;

    call_sv((SV*)arg, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void getaddrinfo_cb(uv_getaddrinfo_t* handle, int status, struct addrinfo* res) {
    SV* sv_status;
    AV* av_res;
    SV* sv_res;
    struct addrinfo* address;
    struct sockaddr_in* in;
    struct sockaddr_in6* in6;
    char ip[INET6_ADDRSTRLEN];
    SV* sv_ip;
    dSP;

    sv_status = sv_2mortal(newSViv(status));

    av_res = (AV*)sv_2mortal((SV*)newAV());
    sv_res = sv_2mortal(newRV_inc((SV*)av_res));

    if (0 == status) {
        for (address = res; address; address = address->ai_next) {
            assert(address->ai_socktype == SOCK_STREAM);

            switch (address->ai_family) {
                case AF_INET:
                    in = (struct sockaddr_in*)address->ai_addr;
                    uv_inet_ntop(AF_INET, &in->sin_addr, ip, INET6_ADDRSTRLEN);
                    sv_ip = newSV(0);
                    sv_setpv(sv_ip, ip);
                    av_push(av_res, sv_ip);
                    break;
                case AF_INET6:
                    in6 = (struct sockaddr_in6*)address->ai_addr;
                    uv_inet_ntop(AF_INET6, &in6->sin6_addr, ip, INET6_ADDRSTRLEN);
                    sv_ip = newSV(0);
                    sv_setpv(sv_ip, ip);
                    av_push(av_res, sv_ip);
                    break;
            }
        }
    }

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_status);
    XPUSHs(sv_res);
    PUTBACK;

    call_sv((SV*)handle->data, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;

    uv_freeaddrinfo(res);
    SvREFCNT_dec(handle->data);
    Safefree(handle);
}

MODULE=UV PACKAGE=UV PREFIX=uv_

PROTOTYPES: DISABLE

BOOT:
{
    HV* stash = gv_stashpv("UV", 1);

    /* errno */
    UV_ERRNO_MAP(UV_ERRNO_CONST_GEN);

    /* handle type */
    UV_HANDLE_TYPE_MAP(UV_CONST_GEN);

    /* req type */
    UV_REQ_TYPE_MAP(UV_CONST_GEN);

    /* run mode */
    newCONSTSUB(stash, "RUN_DEFAULT", newSViv(UV_RUN_DEFAULT));
    newCONSTSUB(stash, "RUN_ONCE", newSViv(UV_RUN_ONCE));
    newCONSTSUB(stash, "RUN_NOWAIT", newSViv(UV_RUN_NOWAIT));

    /* udp */
    newCONSTSUB(stash, "UDP_IPV6ONLY", newSViv(UV_UDP_IPV6ONLY));
    newCONSTSUB(stash, "UDP_PARTIAL", newSViv(UV_UDP_PARTIAL));

    /* udp membership */
    newCONSTSUB(stash, "LEAVE_GROUP", newSViv(UV_LEAVE_GROUP));
    newCONSTSUB(stash, "JOIN_GROUP", newSViv(UV_JOIN_GROUP));

    /* poll */
    newCONSTSUB(stash, "READABLE", newSViv(UV_READABLE));
    newCONSTSUB(stash, "WRITABLE", newSViv(UV_WRITABLE));
}

void
uv_default_loop()
CODE:
{
    SV* sv;
    HV* hv;

    hv = (HV*)sv_2mortal((SV*)newHV());
    sv = sv_2mortal(newRV_inc((SV*)hv));

    sv_bless(sv, gv_stashpv("UV::loop", 1));

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)uv_default_loop();

    ST(0) = sv;
    XSRETURN(1);
}

int
uv_run(int mode = UV_RUN_DEFAULT)
CODE:
{
    RETVAL = uv_run(uv_default_loop(), mode);
}
OUTPUT:
    RETVAL

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
uv_last_error()
CODE:
{
    uv_err_t err;

    err = uv_last_error(uv_default_loop());
    RETVAL = err.code;
}
OUTPUT:
    RETVAL

const char*
uv_strerror(int code)
CODE:
{
    uv_err_t err;
    err.code = code;
    RETVAL = uv_strerror(err);
}
OUTPUT:
    RETVAL

const char*
uv_err_name(int code)
CODE:
{
    uv_err_t err;
    err.code = code;
    RETVAL = uv_err_name(err);
}
OUTPUT:
    RETVAL

int
uv_shutdown(uv_stream_t* handle, SV* cb)
CODE:
{
    uv_shutdown_t* req;
    p5uv_stream_t* p5stream;

    Newx(req, 1, uv_shutdown_t);

    p5stream = (p5uv_stream_t*)handle->data;

    if (p5stream->shutdown_cb)
        SvREFCNT_dec(p5stream->shutdown_cb);
    p5stream->shutdown_cb = SvREFCNT_inc(cb);

    RETVAL = uv_shutdown(req, handle, shutdown_cb);
}
OUTPUT:
    RETVAL

int
uv_is_active(uv_handle_t* handle)

void
uv_walk(SV* cb)
CODE:
{
    uv_walk(uv_default_loop(), walk_cb, SvREFCNT_inc(cb));
    SvREFCNT_dec(cb);
}

void
uv_close(uv_handle_t* handle, SV* cb = NULL)
CODE:
{
    p5uv_handle_t* p5handle = (p5uv_handle_t*)handle->data;

    if (p5handle->close_cb) {
        SvREFCNT_dec(p5handle->close_cb);
        p5handle->close_cb = NULL;
    }

    if (cb) {
        p5handle->close_cb = SvREFCNT_inc(cb);
    }

    uv_close(handle, close_cb);
}

NV
uv_now()
CODE:
{
    /* what's the proper way to return a int64_t? */
    RETVAL = (NV) uv_now(uv_default_loop());
}
OUTPUT:
    RETVAL

int
uv_listen(uv_stream_t* stream, int backlog, SV* cb)
CODE:
{
    p5uv_stream_t* p5stream = (p5uv_stream_t*)stream->data;

    if (p5stream->connection_cb)
        SvREFCNT_dec(p5stream->connection_cb);
    p5stream->connection_cb = SvREFCNT_inc(cb);

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
    p5uv_stream_t* p5stream = (p5uv_stream_t*)stream->data;

    if (p5stream->read_cb)
        SvREFCNT_dec(p5stream->read_cb);
    p5stream->read_cb = SvREFCNT_inc(cb);

    RETVAL = uv_read_start(stream, alloc_cb, read_cb);
}
OUTPUT:
    RETVAL

int
uv_read_stop(uv_stream_t* stream)

int
uv_read2_start(uv_stream_t* stream, SV* cb)
CODE:
{
    p5uv_stream_t* p5stream = (p5uv_stream_t*)stream;

    if (p5stream->read_cb)
        SvREFCNT_dec(p5stream->read_cb);
    p5stream->read_cb = SvREFCNT_inc(cb);

    RETVAL = uv_read2_start(stream, alloc_cb, read2_cb);
}
OUTPUT:
    RETVAL

int
uv_write(uv_stream_t* stream, SV* sv_buf, SV* cb = NULL)
CODE:
{
    p5uv_stream_t* p5stream = (p5uv_stream_t*)stream->data;
    char* buf;
    STRLEN len;
    uv_write_t* req;
    uv_buf_t b;

    if (p5stream->write_cb) {
        SvREFCNT_dec(p5stream->write_cb);
        p5stream->write_cb = NULL;
    }

    if (cb)
        p5stream->write_cb = SvREFCNT_inc(cb);

    Newx(req, 1, uv_write_t);

    buf = SvPV(sv_buf, len);
    b = uv_buf_init(buf, len);

    RETVAL = uv_write(req, stream, &b, 1, write_cb);
}
OUTPUT:
    RETVAL

int
uv_write2(uv_stream_t* stream, SV* sv_buf, uv_stream_t* send_stream, SV* cb = NULL)
CODE:
{
    p5uv_stream_t* p5stream = (p5uv_stream_t*)stream->data;
    char* buf;
    STRLEN len;
    uv_write_t* req;
    uv_buf_t b;

    if (p5stream->write_cb) {
        SvREFCNT_dec(p5stream->write_cb);
        p5stream->write_cb = NULL;
    }

    if (cb)
        p5stream->write_cb = SvREFCNT_inc(cb);

    Newx(req, 1, uv_write_t);

    buf = SvPV(sv_buf, len);
    b = uv_buf_init(buf, len);

    RETVAL = uv_write2(req, stream, &b, 1, send_stream, write_cb);
}
OUTPUT:
    RETVAL

int
uv_is_readable(uv_stream_t* stream);

int
uv_is_writable(uv_stream_t* stream);

int
uv_is_closing(uv_handle_t* handle);

void
uv_tcp_init()
CODE:
{
    uv_tcp_t* tcp;
    int r;

    Newx(tcp, 1, uv_tcp_t);

    r = uv_tcp_init(uv_default_loop(), tcp);
    if (r) {
        croak("cannot initialize tcp handle");
    }

    ST(0) = sv_handle_wrap_init((uv_handle_t*)tcp, UV_TCP);
    XSRETURN(1);
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

void
uv_tcp_getsockname(uv_tcp_t* handle)
CODE:
{
    int r;
    struct sockaddr_storage address;
    struct sockaddr_in* in;
    struct sockaddr_in6* in6;
    int addrlen;
    char ip[INET6_ADDRSTRLEN];

    SV* sv_ip;
    SV* sv_port;

    addrlen = sizeof(address);
    r = uv_tcp_getsockname(handle, (struct sockaddr*)&address, &addrlen);
    assert(0 == r);

    switch (address.ss_family) {
        case AF_INET:
            in = (struct sockaddr_in*)&address;
            uv_inet_ntop(AF_INET, &in->sin_addr, ip, INET6_ADDRSTRLEN);
            sv_ip = sv_2mortal(newSV(0));
            sv_setpv(sv_ip, ip);
            sv_port = sv_2mortal(newSViv(ntohs(in->sin_port)));
            break;
        case AF_INET6:
            in6 = (struct sockaddr_in6*)&address;
            uv_inet_ntop(AF_INET6, &in6->sin6_addr, ip, INET6_ADDRSTRLEN);
            sv_ip = sv_2mortal(newSV(0));
            sv_setpv(sv_ip, ip);
            sv_port = sv_2mortal(newSViv(htons(in6->sin6_port)));
            break;
        default:
            croak("bad family");
    }

    ST(0) = sv_ip;
    ST(1) = sv_port;
    XSRETURN(2);
}

void
uv_tcp_getpeername(uv_tcp_t* handle)
CODE:
{
    int r;
    struct sockaddr_storage address;
    struct sockaddr_in* in;
    struct sockaddr_in6* in6;
    int addrlen;
    char ip[INET6_ADDRSTRLEN];

    SV* sv_ip;
    SV* sv_port;

    addrlen = sizeof(address);
    r = uv_tcp_getpeername(handle, (struct sockaddr*)&address, &addrlen);
    assert(0 == r);

    switch (address.ss_family) {
        case AF_INET:
            in = (struct sockaddr_in*)&address;
            uv_inet_ntop(AF_INET, &in->sin_addr, ip, INET6_ADDRSTRLEN);
            sv_ip = sv_2mortal(newSV(0));
            sv_setpv(sv_ip, ip);
            sv_port = sv_2mortal(newSViv(ntohs(in->sin_port)));
            break;
        case AF_INET6:
            in6 = (struct sockaddr_in6*)&address;
            uv_inet_ntop(AF_INET6, &in6->sin6_addr, ip, INET6_ADDRSTRLEN);
            sv_ip = sv_2mortal(newSV(0));
            sv_setpv(sv_ip, ip);
            sv_port = sv_2mortal(newSViv(htons(in6->sin6_port)));
            break;
        default:
            croak("bad family");
    }

    ST(0) = sv_ip;
    ST(1) = sv_port;
    XSRETURN(2);
}

int
uv_tcp_connect(uv_tcp_t* tcp, const char* ip, int port, SV* cb)
CODE:
{
    uv_connect_t* req;
    p5uv_tcp_t* p5tcp = (p5uv_tcp_t*)tcp->data;

    if (p5tcp->connect_cb)
        SvREFCNT_dec(p5tcp->connect_cb);
    p5tcp->connect_cb = SvREFCNT_inc(cb);

    Newx(req, 1, uv_connect_t);

    RETVAL = uv_tcp_connect(req, tcp, uv_ip4_addr(ip, port), connect_cb);
}
OUTPUT:
    RETVAL

int
uv_tcp_connect6(uv_tcp_t* tcp, const char* ip, int port, SV* cb)
CODE:
{
    uv_connect_t* req;
    p5uv_tcp_t* p5tcp = (p5uv_tcp_t*)tcp->data;

    if (p5tcp->connect_cb)
        SvREFCNT_dec(p5tcp->connect_cb);
    p5tcp->connect_cb = SvREFCNT_inc(cb);

    Newx(req, 1, uv_connect_t);

    RETVAL = uv_tcp_connect6(req, tcp, uv_ip6_addr(ip, port), connect_cb);
}
OUTPUT:
    RETVAL

void
uv_udp_init()
CODE:
{
    uv_udp_t* udp;
    int r;

    Newx(udp, 1, uv_udp_t);

    r = uv_udp_init(uv_default_loop(), udp);
    if (r) {
        croak("cannot initialize udp handle");
    }

    ST(0) = sv_handle_wrap_init((uv_handle_t*)udp, UV_UDP);
    XSRETURN(1);
}

int
uv_udp_bind(uv_udp_t* udp, const char* ip, int port, int flags = 0)
CODE:
{
    RETVAL = uv_udp_bind(udp, uv_ip4_addr(ip, port), flags);
}
OUTPUT:
    RETVAL

int
uv_udp_bind6(uv_udp_t* udp, const char* ip, int port, int flags = 0)
CODE:
{
    RETVAL = uv_udp_bind6(udp, uv_ip6_addr(ip, port), flags);
}
OUTPUT:
    RETVAL

void
uv_udp_getsockname(uv_udp_t* udp)
CODE:
{
    struct sockaddr_storage address;
    struct sockaddr_in* in;
    struct sockaddr_in6* in6;
    char ip[INET6_ADDRSTRLEN];
    int addrlen;
    int r;
    SV* sv_ip;
    SV* sv_port;

    addrlen = sizeof(address);
    r = uv_udp_getsockname(udp, (struct sockaddr*)&address, &addrlen);
    assert(0 == r);

    switch (address.ss_family) {
        case AF_INET:
            in = (struct sockaddr_in*)&address;
            uv_inet_ntop(AF_INET, &in->sin_addr, ip, INET6_ADDRSTRLEN);
            sv_ip = sv_2mortal(newSV(0));
            sv_setpv(sv_ip, ip);
            sv_port = sv_2mortal(newSViv(ntohs(in->sin_port)));
            break;
        case AF_INET6:
            in6 = (struct sockaddr_in6*)&address;
            uv_inet_ntop(AF_INET6, &in6->sin6_addr, ip, INET6_ADDRSTRLEN);
            sv_ip = sv_2mortal(newSV(0));
            sv_setpv(sv_ip, ip);
            sv_port = sv_2mortal(newSViv(ntohs(in6->sin6_port)));
            break;
        default:
            croak("bad address family");
    }

    ST(0) = sv_ip;
    ST(1) = sv_port;
    XSRETURN(2);
}

int
uv_udp_set_membership(uv_udp_t* udp, const char* multicast_addr, const char* interface_addr, int membership)

int
uv_udp_set_multicast_loop(uv_udp_t* udp, int on);

int
uv_udp_set_multicast_ttl(uv_udp_t* udp, int ttl);

int
uv_udp_set_broadcast(uv_udp_t* udp, int on);

int
uv_udp_set_ttl(uv_udp_t* udp, int ttl);

int
uv_udp_send(uv_udp_t* udp, SV* sv_buf, const char* ip, int port, SV* cb = NULL)
CODE:
{
    p5uv_udp_t* p5udp = (p5uv_udp_t*)udp->data;
    char* buf;
    STRLEN len;
    uv_udp_send_t* req;
    uv_buf_t b;

    if (p5udp->send_cb) {
        SvREFCNT_dec(p5udp->send_cb);
        p5udp->send_cb = NULL;
    }

    if (cb) {
        p5udp->send_cb = SvREFCNT_inc(cb);
    }

    Newx(req, 1, uv_udp_send_t);

    buf = SvPV(sv_buf, len);
    b   = uv_buf_init(buf, len);

    RETVAL = uv_udp_send(req, udp, &b, 1, uv_ip4_addr(ip, port), send_cb);
}
OUTPUT:
    RETVAL

int
uv_udp_send6(uv_udp_t* udp, SV* sv_buf, const char* ip, int port, SV* cb = NULL)
CODE:
{
    p5uv_udp_t* p5udp = (p5uv_udp_t*)udp->data;
    char* buf;
    STRLEN len;
    uv_udp_send_t* req;
    uv_buf_t b;

    if (p5udp->send_cb) {
        SvREFCNT_dec(p5udp->send_cb);
        p5udp->send_cb = NULL;
    }

    if (cb) {
        p5udp->send_cb = SvREFCNT_inc(cb);
    }

    Newx(req, 1, uv_udp_send_t);

    buf = SvPV(sv_buf, len);
    b   = uv_buf_init(buf, len);

    RETVAL = uv_udp_send6(req, udp, &b, 1, uv_ip6_addr(ip, port), send_cb);
}
OUTPUT:
    RETVAL

int
uv_udp_recv_start(uv_udp_t* udp, SV* cb)
CODE:
{
    p5uv_udp_t* p5udp = (p5uv_udp_t*)udp->data;

    if (p5udp->recv_cb)
        SvREFCNT_dec(p5udp->recv_cb);
    p5udp->recv_cb = SvREFCNT_inc(cb);

    RETVAL = uv_udp_recv_start(udp, alloc_cb, recv_cb);
}
OUTPUT:
    RETVAL

int
uv_udp_recv_stop(uv_udp_t* udp)

void
uv_tty_init(int fd, int readable)
CODE:
{
    uv_tty_t* tty;
    int r;

    Newx(tty, 1, uv_tty_t);

    r = uv_tty_init(uv_default_loop(), tty, fd, readable);
    if (r) {
        croak("cannot initialize tty handle");
    }

    ST(0) = sv_handle_wrap_init((uv_handle_t*)tty, UV_TTY);
    XSRETURN(1);
}

int
uv_tty_set_mode(uv_tty_t* tty, int mode)

void
uv_tty_reset_mode()

void
uv_tty_get_winsize(uv_tty_t* tty)
CODE:
{
    int width, height;
    int r;
    SV* sv_width;
    SV* sv_height;

    r = uv_tty_get_winsize(tty, &width, &height);
    assert(0 == r);

    sv_width = sv_2mortal(newSViv(width));
    sv_height = sv_2mortal(newSViv(height));

    ST(0) = sv_width;
    ST(1) = sv_height;
    XSRETURN(2);
}

void
uv_poll_init(int fd)
CODE:
{
    uv_poll_t* poll;
    int r;

    Newx(poll, 1, uv_poll_t);

    r = uv_poll_init(uv_default_loop(), poll, fd);
    if (r) {
        croak("cannot initialize poll handle");
    }

    ST(0) = sv_handle_wrap_init((uv_handle_t*)poll, UV_POLL);
    XSRETURN(1);
}

int
uv_poll_start(uv_poll_t* handle, int events, SV* cb)
CODE:
{
    p5uv_poll_t* p5poll = (p5uv_poll_t*)handle->data;

    if (p5poll->cb)
        SvREFCNT_dec(p5poll->cb);
    p5poll->cb = SvREFCNT_inc(cb);

    RETVAL = uv_poll_start(handle, events, poll_cb);
}
OUTPUT:
    RETVAL

int
uv_poll_stop(uv_poll_t* handle)

int
uv_guess_handle(int fd)

void
uv_pipe_init(int ipc)
CODE:
{
    uv_pipe_t* pipe;
    int r;

    Newx(pipe, 1, uv_pipe_t);

    r = uv_pipe_init(uv_default_loop(), pipe, ipc);
    if (r) {
        croak("cannot initialize pipe handle");
    }

    ST(0) = sv_handle_wrap_init((uv_handle_t*)pipe, UV_NAMED_PIPE);
    XSRETURN(1);
}

void
uv_pipe_open(uv_pipe_t* pipe, int fd)

int
uv_pipe_bind(uv_pipe_t* pipe, const char* name)

void
uv_pipe_connect(uv_pipe_t* pipe, const char* name, SV* cb)
CODE:
{
    uv_connect_t* req;
    p5uv_pipe_t* p5pipe = (p5uv_pipe_t*)pipe->data;

    if (p5pipe->connect_cb)
        SvREFCNT_dec(p5pipe->connect_cb);
    p5pipe->connect_cb = SvREFCNT_inc(cb);

    Newx(req, 1, uv_connect_t);

    uv_pipe_connect(req, pipe, name, connect_cb);
}

void
uv_prepare_init()
CODE:
{
    uv_prepare_t* prepare;
    int r;

    Newx(prepare, 1, uv_prepare_t);

    r = uv_prepare_init(uv_default_loop(), prepare);
    if (r) {
        croak("cannot initialize prepare handle");
    }

    ST(0) = sv_handle_wrap_init((uv_handle_t*)prepare, UV_PREPARE);
    XSRETURN(1);
}

int
uv_prepare_start(uv_prepare_t* prepare, SV* cb)
CODE:
{
    p5uv_prepare_t* p5prepare = (p5uv_prepare_t*)prepare->data;

    if (p5prepare->cb)
        SvREFCNT_dec(p5prepare->cb);
    p5prepare->cb = SvREFCNT_inc(cb);

    RETVAL = uv_prepare_start(prepare, prepare_cb);
}
OUTPUT:
    RETVAL

int
uv_prepare_stop(uv_prepare_t* prepare)

void
uv_check_init()
CODE:
{
    uv_check_t* check;
    int r;

    Newx(check, 1, uv_check_t);

    r = uv_check_init(uv_default_loop(), check);
    if (r) {
        croak("cannot initialize check handle");
    }

    ST(0) = sv_handle_wrap_init((uv_handle_t*)check, UV_CHECK);
    XSRETURN(1);
}

int
uv_check_start(uv_check_t* check, SV* cb)
CODE:
{
    p5uv_check_t* p5check = (p5uv_check_t*)check->data;

    if (p5check->cb)
        SvREFCNT_dec(p5check->cb);
    p5check->cb = SvREFCNT_inc(cb);

    RETVAL = uv_check_start(check, check_cb);
}
OUTPUT:
    RETVAL

int
uv_check_stop(uv_check_t* check)

void
uv_idle_init()
CODE:
{
    uv_idle_t* idle;
    int r;

    Newx(idle, 1, uv_idle_t);

    r = uv_idle_init(uv_default_loop(), idle);
    if (r) {
        croak("cannot initialize idle handle");
    }

    ST(0) = sv_handle_wrap_init((uv_handle_t*)idle, UV_IDLE);
    XSRETURN(1);
}

int
uv_idle_start(uv_idle_t* idle, SV* cb)
CODE:
{
    p5uv_idle_t* p5idle = (p5uv_idle_t*)idle->data;

    if (p5idle->cb)
        SvREFCNT_dec(p5idle->cb);
    p5idle->cb = SvREFCNT_inc(cb);

    RETVAL = uv_idle_start(idle, idle_cb);
}
OUTPUT:
    RETVAL

int
uv_idle_stop(uv_idle_t* idle)

void
uv_async_init(SV* cb)
CODE:
{
    SV* sv_async;
    uv_async_t* async;
    p5uv_async_t* p5async;
    int r;

    Newx(async, 1, uv_async_t);

    r = uv_async_init(uv_default_loop(), async, async_cb);
    if (r) {
        croak("cannot initialize async handle");
    }

    sv_async = sv_handle_wrap_init((uv_handle_t*)async, UV_ASYNC);

    p5async = (p5uv_async_t*)async->data;
    p5async->cb = SvREFCNT_inc(cb);

    ST(0) = sv_async;
    XSRETURN(1);
}

int
uv_async_send(uv_async_t* async)

void
uv_timer_init()
CODE:
{
    uv_timer_t* timer;
    int r;

    Newx(timer, 1, uv_timer_t);

    r = uv_timer_init(uv_default_loop(), timer);
    if (r) {
        croak("cannot initialize timer handle");
    }

    ST(0) = sv_handle_wrap_init((uv_handle_t*)timer, UV_TIMER);
    XSRETURN(1);
}

int
uv_timer_start(uv_timer_t* timer, double timeout, double repeat, SV* cb)
CODE:
{
    p5uv_timer_t* p5timer = (p5uv_timer_t*)timer->data;

    if (p5timer->cb)
        SvREFCNT_dec(p5timer->cb);
    p5timer->cb = SvREFCNT_inc(cb);

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

int
uv_getaddrinfo(const char* node, SV* sv_service, SV* cb, int hint = 0)
CODE:
{
    uv_getaddrinfo_t* handle;
    struct addrinfo hints;
    int fam;
    char* service = NULL;

    if (SvPOK(sv_service)) {
        service = SvPV_nolen(sv_service);
    }

    fam = AF_UNSPEC;
    switch (hint) {
        case 4:
            fam = AF_INET;
            break;
        case 6:
            fam = AF_INET6;
            break;
    }

    Newx(handle, 1, uv_getaddrinfo_t);

    handle->data = (void*)SvREFCNT_inc(cb);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = fam;
    hints.ai_socktype = SOCK_STREAM;

    RETVAL = uv_getaddrinfo(uv_default_loop(), handle, getaddrinfo_cb, node, service, &hints);
}
OUTPUT:
    RETVAL

MODULE=UV PACKAGE=UV::loop

unsigned int
active_handles(SV* sv_loop)
CODE:
{
    MAGIC* m;

    if (!SvROK(sv_loop)) {
        croak("Usage: UV::default_loop->active_handles");
    }

    m = mg_find(SvRV(sv_loop), PERL_MAGIC_ext);
    if (!m) {
        croak("invalid UV::loop object");
    }

    uv_loop_t* loop = (uv_loop_t*)m->mg_obj;
    RETVAL = loop->active_handles;
}
OUTPUT:
    RETVAL

MODULE=UV PACKAGE=UV::handle

int
type(uv_handle_t* handle)
CODE:
{
    RETVAL = handle->type;
}
OUTPUT:
    RETVAL

