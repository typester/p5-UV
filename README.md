# UV [![Build Status](https://secure.travis-ci.org/typester/p5-UV.png?branch=master)](http://travis-ci.org/typester/p5-UV)

UV is perl interface to [libuv](https://github.com/joyent/libuv).

## Build instructions

    $ git clone git://github.com/typester/p5-UV.git
    $ cd p5-UV
    $ git submodule update --init --recursive
    $ echo -n | cpanm Module::Install::XSUtil
    $ cpanm --installdeps .
    $ make test
    $ make install

## Current status

Not all functions implemented at this time.

Supported functions is:

* `uv_run` (`UV::run`)
* `uv_version` (`UV::version`)
* `uv_last_error` (`UV::last_error`)
* `uv_strerror` (`UV::strerror`)
* `uv_err_name` (`UV::err_name`)
* `uv_shutdown` (`UV::shutdown`)
* `uv_is_active` (`UV::is_active`)
* `uv_close` (`UV::close`)
* `uv_listen` (`UV::listen`)
* `uv_accept` (`UV::accept`)
* `uv_read_start` (`UV::read_start`)
* `uv_read_stop` (`UV::read_stop`)
* `uv_read2_start` (`UV::read2_start`)
* `uv_write` (`UV::write`)
* `uv_write2` (`UV::write2`)
* `uv_is_readable` (`UV::is_readable`)
* `uv_is_writable` (`UV::is_writable`)
* `uv_is_closing` (`UV::is_closing`)
* `uv_tcp_*` (`UV::tcp_*`)
* `uv_udp_*` (`UV::udp_*`)
* `uv_tty_*` (`UV::tty_*`)
* `uv_guess_handle` (`UV::guess_handle`)
* `uv_pipe_*` (`UV::pipe_*`)
* `uv_prepare_*` (`UV::prepare_*`)
* `uv_check_*` (`UV::check_*`)
* `uv_idle_*` (`UV::idle_*`)
* `uv_async_*` (`UV::async_*`)
* `uv_timer_*` (`UV::timer_*`)
* `uv_getaddrinfo` (`UV::getaddrinfo`)



