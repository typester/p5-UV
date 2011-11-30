#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"
#define NEED_sv_2pvbyte
#include "ppport.h"

#include <assert.h>
#include <stdlib.h>

#include <uv.h>

static void close_cb(uv_handle_t* handle) {
    if (NULL != handle->data) {
        SvREFCNT_dec((SV*)handle->data);
    }

    free(handle);
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

static void xs_uv_cose(uv_handle_t* handle) {
    free(handle);
}

MODULE=UV PACKAGE=UV

PROTOTYPES: DISABLE

void
run()
CODE:
{
    uv_run(uv_default_loop());
}

void
version()
CODE:
{
    SV* sv;

    sv = sv_2mortal(newSV(0));
    sv_setpvf(sv, "%d.%d", UV_VERSION_MAJOR, UV_VERSION_MINOR);

    ST(0) = sv;
}

MODULE=UV PACKAGE=UV::timer

void
new(char* class, double timeout, double repeat, SV* cb)
CODE:
{
    SV* timer_sv;
    uv_timer_t* timer;
    HV* hv;
    HV* stash;
    int r;

    hv       = (HV*)sv_2mortal((SV*)newHV());
    timer_sv = sv_2mortal(newRV_inc((SV*)hv));

    stash = gv_stashpv(class, 0);
    assert(NULL != stash);
    sv_bless(timer_sv, stash);

    timer = (uv_timer_t*)malloc(sizeof(uv_timer_t));
    assert(timer);

    r = uv_timer_init(uv_default_loop(), timer);
    assert(0 == r);

    timer->data = (void*)SvREFCNT_inc(cb);

    r = uv_timer_start(timer, timer_cb, (int64_t)timeout, (int64_t)repeat);
    assert(0 == r);

    sv_magic((SV*)hv, NULL, PERL_MAGIC_ext, NULL, 0);
    mg_find((SV*)hv, PERL_MAGIC_ext)->mg_obj = (SV*)timer;

    ST(0) = timer_sv;
}

void
DESTROY(SV* timer_sv)
CODE:
{
    MAGIC* m;
    uv_timer_t* timer = NULL;
    int r;

    m = mg_find(SvRV(timer_sv), PERL_MAGIC_ext);
    if (NULL != m) timer = (uv_timer_t*)m->mg_obj;
    if (NULL == timer) croak("This is not UV::timer object\n");

    r = uv_timer_stop(timer);
    assert(0 == r);

    uv_close((uv_handle_t*)timer, close_cb);
}
