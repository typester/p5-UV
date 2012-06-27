#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#define NEED_sv_2pvbyte
#include "ppport.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

/* from node.js, will remove when libuv support this
 * Temporary hack: libuv should provide uv_inet_pton and uv_inet_ntop.
 */
#if defined(_MSC_VER)
  extern "C" {
#   include <inet_net_pton.h>
#   include <inet_ntop.h>
  }
# define uv_inet_pton ares_inet_pton
#elif defined(__MINGW32__)
# define uv_inet_ntop ares_inet_ntop

#else // __POSIX__
# include <arpa/inet.h>
# define uv_inet_pton inet_pton
# define uv_inet_ntop inet_ntop
#endif

#define UV_ERRNO_CONST_GEN(val, name, s) \
    newCONSTSUB(stash, #name, newSViv(val));

typedef struct {
    SV* connection_cb;
    SV* connect_cb;
    SV* read_cb;
    SV* write_cb;
    SV* shutdown_cb;
} cb_pair_t;

static void shutdown_cb(uv_shutdown_t* req, int status) {
    uv_stream_t* stream = req->handle;
    cb_pair_t* cb_pair = (cb_pair_t*)stream->data;
    SV* sv_status;
    dSP;

    sv_status = sv_2mortal(newSViv(status));

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    call_sv(cb_pair->shutdown_cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;

    free(req);
}

static void close_cb(uv_handle_t* handle) {
    cb_pair_t* pair;

    if (UV_TIMER   == handle->type || UV_IDLE == handle->type
     || UV_PREPARE == handle->type || UV_CHECK == handle->type
     || UV_ASYNC   == handle->type)
    {
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

static void read2_cb(uv_pipe_t* pipe, ssize_t nread, uv_buf_t buf, uv_handle_type pending) {
    SV* cb;
    SV* sv_nread;
    SV* sv_buf;
    SV* sv_pending;

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

    cb = ((cb_pair_t*)pipe->data)->read_cb;

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

static void send_cb(uv_udp_send_t* req, int status) {
    uv_udp_t* udp      = req->handle;
    cb_pair_t* cb_pair = (cb_pair_t*)udp->data;
    SV* sv_status;
    dSP;

    if (cb_pair->write_cb) {
        ENTER;
        SAVETMPS;

        sv_status = sv_2mortal(newSViv(status));

        PUSHMARK(SP);
        XPUSHs(sv_status);
        PUTBACK;

        call_sv(cb_pair->write_cb, G_SCALAR);

        SPAGAIN;

        PUTBACK;
        FREETMPS;
        LEAVE;
    }

    free(req);
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

    call_sv(((cb_pair_t*)handle->data)->read_cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;

    free(buf.base);
}

static void prepare_cb(uv_prepare_t* handle, int status) {
    SV* cb = (SV*)handle->data;
    SV* sv_status;
    dSP;

    sv_status = sv_2mortal(newSViv(status));

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    call_sv(cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void check_cb(uv_check_t* handle, int status) {
    SV* cb = (SV*)handle->data;
    SV* sv_status;
    dSP;

    sv_status = sv_2mortal(newSViv(status));

    ENTER;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    call_sv(cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void idle_cb(uv_idle_t* handle, int status) {
    SV* cb;
    SV* sv_status;

    dSP;

    ENTER;
    SAVETMPS;

    sv_status = sv_2mortal(newSViv(status));

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    cb = (SV*)handle->data;

    call_sv(cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void async_cb(uv_async_t* handle, int status) {
    SV* cb;
    SV* sv_status;

    dSP;

    ENTER;
    SAVETMPS;

    sv_status = sv_2mortal(newSViv(status));

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    cb = (SV*)handle->data;

    call_sv(cb, G_SCALAR);

    SPAGAIN;

    PUTBACK;
    FREETMPS;
    LEAVE;
}

static void timer_cb(uv_timer_t* handle, int status) {
    SV* cb;
    SV* sv_status;

    dSP;

    ENTER;
    SAVETMPS;

    sv_status = sv_2mortal(newSViv(status));

    PUSHMARK(SP);
    XPUSHs(sv_status);
    PUTBACK;

    cb = (SV*)handle->data;

    call_sv(cb, G_SCALAR);

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
    free(handle);
}

MODULE=UV PACKAGE=UV PREFIX=uv_

PROTOTYPES: DISABLE

BOOT:
{
    HV* stash = gv_stashpv("UV", 1);

    /* errno */
    UV_ERRNO_MAP(UV_ERRNO_CONST_GEN);

    /* handle type */
    newCONSTSUB(stash, "UNKNOWN_HANDLE", newSViv(UV_UNKNOWN_HANDLE));
    newCONSTSUB(stash, "ASYNC", newSViv(UV_ASYNC));
    newCONSTSUB(stash, "CHECK", newSViv(UV_CHECK));
    newCONSTSUB(stash, "FS_EVENT", newSViv(UV_FS_EVENT));
    newCONSTSUB(stash, "IDLE", newSViv(UV_IDLE));
    newCONSTSUB(stash, "NAMED_PIPE", newSViv(UV_NAMED_PIPE));
    newCONSTSUB(stash, "POLL", newSViv(UV_POLL));
    newCONSTSUB(stash, "PREPARE", newSViv(UV_PREPARE));
    newCONSTSUB(stash, "PROCESS", newSViv(UV_PROCESS));
    newCONSTSUB(stash, "TCP", newSViv(UV_TCP));
    newCONSTSUB(stash, "TIMER", newSViv(UV_TIMER));
    newCONSTSUB(stash, "TTY", newSViv(UV_TTY));
    newCONSTSUB(stash, "UDP", newSViv(UV_UDP));
    newCONSTSUB(stash, "ARES_TASK", newSViv(UV_ARES_TASK));
    newCONSTSUB(stash, "FILE", newSViv(UV_FILE));

    /* udp */
    newCONSTSUB(stash, "UDP_IPV6ONLY", newSViv(UV_UDP_IPV6ONLY));
    newCONSTSUB(stash, "UDP_PARTIAL", newSViv(UV_UDP_PARTIAL));

    /* udp membership */
    newCONSTSUB(stash, "LEAVE_GROUP", newSViv(UV_LEAVE_GROUP));
    newCONSTSUB(stash, "JOIN_GROUP", newSViv(UV_JOIN_GROUP));
}

void
uv_run()
CODE:
{
    uv_run(uv_default_loop());
}

void
uv_run_once()
CODE:
{
    uv_run_once(uv_default_loop());
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
    cb_pair_t* cb_pair;

    req = (uv_shutdown_t*)malloc(sizeof(uv_shutdown_t));
    assert(req);

    cb_pair = (cb_pair_t*)handle->data;

    if (cb_pair->shutdown_cb)
        SvREFCNT_dec(cb_pair->shutdown_cb);
    cb_pair->shutdown_cb = SvREFCNT_inc(cb);

    RETVAL = uv_shutdown(req, handle, shutdown_cb);
}
OUTPUT:
    RETVAL

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
uv_read2_start(uv_stream_t* stream, SV* cb)
CODE:
{
    cb_pair_t* cb_pair = (cb_pair_t*)stream->data;

    if (cb_pair->read_cb)
        SvREFCNT_dec(cb_pair->read_cb);
    cb_pair->read_cb = SvREFCNT_inc(cb);

    RETVAL = uv_read2_start(stream, alloc_cb, read2_cb);
}
OUTPUT:
    RETVAL

int
uv_write(uv_stream_t* stream, SV* sv_buf, SV* cb = NULL)
CODE:
{
    cb_pair_t* cb_pair = (cb_pair_t*)stream->data;
    char* buf;
    STRLEN len;
    uv_write_t* req;
    uv_buf_t b;

    if (cb_pair->write_cb) {
        SvREFCNT_dec(cb_pair->write_cb);
        cb_pair->write_cb = NULL;
    }

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

int
uv_write2(uv_stream_t* stream, SV* sv_buf, uv_stream_t* send_stream, SV* cb = NULL)
CODE:
{
    cb_pair_t* cb_pair = (cb_pair_t*)stream->data;
    char* buf;
    STRLEN len;
    uv_write_t* req;
    uv_buf_t b;

    if (cb_pair->write_cb) {
        SvREFCNT_dec(cb_pair->write_cb);
        cb_pair->write_cb = NULL;
    }

    if (cb)
        cb_pair->write_cb = SvREFCNT_inc(cb);

    req = (uv_write_t*)malloc(sizeof(uv_write_t));
    assert(req);

    buf = SvPV(sv_buf, len);
    b   = uv_buf_init(buf, len);

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
uv_udp_init()
CODE:
{
    SV* sv_udp;
    uv_udp_t* udp;
    HV* hv;
    int r;

    hv = (HV*)sv_2mortal((SV*)newHV());
    sv_udp = sv_2mortal(newRV_inc((SV*)hv));

    sv_bless(sv_udp, gv_stashpv("UV::udp", 1));

    udp = (uv_udp_t*)malloc(sizeof(uv_udp_t));
    assert(udp);

    r = uv_udp_init(uv_default_loop(), udp);
    assert(0 == r);

    udp->data = (void*)calloc(1, sizeof(cb_pair_t));

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)udp;

    ST(0) = sv_udp;
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
    cb_pair_t* cb_pair = (cb_pair_t*)udp->data;
    char* buf;
    STRLEN len;
    uv_udp_send_t* req;
    uv_buf_t b;

    if (cb_pair->write_cb)
        SvREFCNT_dec(cb_pair->write_cb);
    if (cb)
        cb_pair->write_cb = SvREFCNT_inc(cb);

    req = (uv_udp_send_t*)malloc(sizeof(uv_udp_send_t));
    assert(req);

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
    cb_pair_t* cb_pair = (cb_pair_t*)udp->data;
    char* buf;
    STRLEN len;
    uv_udp_send_t* req;
    uv_buf_t b;

    if (cb_pair->write_cb)
        SvREFCNT_dec(cb_pair->write_cb);
    if (cb)
        cb_pair->write_cb = SvREFCNT_inc(cb);

    req = (uv_udp_send_t*)malloc(sizeof(uv_udp_send_t));
    assert(req);

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
    cb_pair_t* cb_pair = (cb_pair_t*)udp->data;

    if (cb_pair->read_cb)
        SvREFCNT_dec(cb_pair->read_cb);
    cb_pair->read_cb = SvREFCNT_inc(cb);

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
    SV* sv_tty;
    uv_tty_t* tty;
    HV* hv;
    int r;

    hv = (HV*)sv_2mortal((SV*)newHV());
    sv_tty = sv_2mortal(newRV_inc((SV*)hv));

    sv_bless(sv_tty, gv_stashpv("UV::tty", 1));

    tty = (uv_tty_t*)malloc(sizeof(uv_tty_t));
    assert(tty);

    r = uv_tty_init(uv_default_loop(), tty, fd, readable);
    assert(0 == r);

    tty->data = (void*)calloc(1, sizeof(cb_pair_t));
    assert(tty->data);

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)tty;

    ST(0) = sv_tty;
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

int
uv_guess_handle(int fd)

void
uv_pipe_init(int ipc)
CODE:
{
    SV* sv_pipe;
    uv_pipe_t* pipe;
    HV* hv;
    int r;

    hv = (HV*)sv_2mortal((SV*)newHV());
    sv_pipe = sv_2mortal(newRV_inc((SV*)hv));

    sv_bless(sv_pipe, gv_stashpv("UV::pipe", 1));

    pipe = (uv_pipe_t*)malloc(sizeof(uv_pipe_t));
    assert(pipe);

    r = uv_pipe_init(uv_default_loop(), pipe, ipc);
    assert(0 == r);

    pipe->data = (void*)calloc(1, sizeof(cb_pair_t));

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)pipe;

    ST(0) = sv_pipe;
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
    cb_pair_t* cb_pair = (cb_pair_t*)pipe->data;

    if (cb_pair->connect_cb)
        SvREFCNT_dec(cb_pair->connect_cb);
    cb_pair->connect_cb = SvREFCNT_inc(cb);

    req = (uv_connect_t*)malloc(sizeof(uv_connect_t));
    assert(req);

    uv_pipe_connect(req, pipe, name, connect_cb);
}

void
uv_prepare_init()
CODE:
{
    SV* sv_prepare;
    uv_prepare_t* prepare;
    HV* hv;
    int r;

    hv = (HV*)sv_2mortal((SV*)newHV());
    sv_prepare = sv_2mortal(newRV_inc((SV*)hv));

    sv_bless(sv_prepare, gv_stashpv("UV::prepare", 1));

    prepare = (uv_prepare_t*)malloc(sizeof(uv_prepare_t));
    assert(prepare);

    r = uv_prepare_init(uv_default_loop(), prepare);
    assert(0 == r);

    prepare->data = NULL;

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)prepare;

    ST(0) = sv_prepare;
    XSRETURN(1);
}

int
uv_prepare_start(uv_prepare_t* prepare, SV* cb)
CODE:
{
    if (prepare->data) {
        SvREFCNT_dec((SV*)prepare->data);
        prepare->data = NULL;
    }
    if (cb) {
        prepare->data = (void*)SvREFCNT_inc(cb);
    }

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
    SV* sv_check;
    uv_check_t* check;
    HV* hv;
    int r;

    hv = (HV*)sv_2mortal((SV*)newHV());
    sv_check = sv_2mortal(newRV_inc((SV*)hv));

    sv_bless(sv_check, gv_stashpv("UV::check", 1));

    check = (uv_check_t*)malloc(sizeof(uv_check_t));
    assert(check);

    r = uv_check_init(uv_default_loop(), check);
    assert(0 == r);

    check->data = NULL;

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)check;

    ST(0) = sv_check;
    XSRETURN(1);
}

int
uv_check_start(uv_check_t* check, SV* cb)
CODE:
{
    if (check->data) {
        SvREFCNT_dec((SV*)check->data);
        check->data = NULL;
    }

    if (cb) {
        check->data = SvREFCNT_inc(cb);
    }

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
    SV* sv_idle;
    uv_idle_t* idle;
    HV* hv;
    int r;

    hv      = (HV*)sv_2mortal((SV*)newHV());
    sv_idle = sv_2mortal(newRV_inc((SV*)hv));

    sv_bless(sv_idle, gv_stashpv("UV::idle", 1));

    idle = (uv_idle_t*)malloc(sizeof(uv_idle_t));
    assert(idle);

    r = uv_idle_init(uv_default_loop(), idle);
    assert(0 == r);
    idle->data = NULL;

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)idle;

    ST(0) = sv_idle;
    XSRETURN(1);
}

int
uv_idle_start(uv_idle_t* idle, SV* cb)
CODE:
{
    if (idle->data)
        SvREFCNT_dec((SV*)idle->data);
    idle->data = (void*)SvREFCNT_inc(cb);

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
    HV* hv;
    int r;

    hv = (HV*)sv_2mortal((SV*)newHV());
    sv_async = sv_2mortal(newRV_inc((SV*)hv));

    sv_bless(sv_async, gv_stashpv("UV::async", 1));

    async = (uv_async_t*)malloc(sizeof(uv_async_t));
    assert(async);

    r = uv_async_init(uv_default_loop(), async, async_cb);

    async->data = (void*)SvREFCNT_inc(cb);

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)async;

    ST(0) = sv_async;
    XSRETURN(1);
}

int
uv_async_send(uv_async_t* async)

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

    handle = (uv_getaddrinfo_t*)malloc(sizeof(uv_getaddrinfo_t));
    assert(handle);

    handle->data = (void*)SvREFCNT_inc(cb);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = fam;
    hints.ai_socktype = SOCK_STREAM;

    RETVAL = uv_getaddrinfo(uv_default_loop(), handle, getaddrinfo_cb, node, service, &hints);
}
OUTPUT:
    RETVAL
