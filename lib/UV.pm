package UV;
use strict;
use XSLoader;

our $VERSION = '0.12';

XSLoader::load __PACKAGE__, $VERSION;

1;

__END__

=head1 NAME

UV - perl interface to libuv

=head1 SYNOPSIS

    use UV;
    
    # TIMERS
    my $timer = UV::timer_init();
    UV::timer_start($timer, 2000, 0, sub {
        warn "is called after 2000ms";
    });
    
    my $timer = UV::timer_init();
    UV::timer_start($timer, 2000, 2000, sub {
        warn "is called roughly every 2s (repeat = 2)";
    });
    
    UV::timer_stop($timer); # stop timer
    UV::close($timer); # destroy timer object
    
    # IO (Simple tcp echo server)
    my $server = UV::tcp_init();
    UV::tcp_bind($server, '0.0.0.0', 5000)
        && die 'bind error: ', UV::strerror(UV::last_error());
    
    UV::listen($server, 10, sub {
        my $client = UV::tcp_init();
        UV::accept($server, $client) && die 'accept failed: ', UV::strerror(UV::last_error());
    
        UV::read_start($client, sub {
            my ($nread, $buf) = @_;
    
            if ($nread < 0) {
                my $err = UV::last_error();
                if ($err != UV::EOF) {
                    warn 'client read error: ', UV::strerror($err);
                }
                UV::close($client);
            }
            elsif ($nread == 0) {
                # nothing to read
            }
            else {
                UV::write($client, $buf, sub {
                    my ($status) = @_;
    
                    if ($status) {
                        warn 'client write error: ', UV::strerror(UV::last_error());
                        UV::close($client);
                    }
                });
            }
        });
    
    }) && die 'listen error: ', UV::strerror(UV::last_error());
    
    # MAINLOOP
    UV::run()

=head1 DESCRIPTION

UV provides low-level interface to libuv, https://github.com/joyent/libuv, platform layer for node.js.

Low-level means this module's functions maps to libuv functions directry.
C<uv_listen> maps to C<UV::listen>, C<uv_tcp_connect> to C<UV::tcp_connect>, and so on.

This is because I'm using this module to make some prototypes for native C application which uses libuv.
Perl codes using this module can be easily converted to C programs.

=head1 CAUTION

Currently this module is in early development stage. The APIs are still fluid, and may change.

=head1 THERE IS SOME LIMITATIONS AT THIS TIME

No file-system apis, no threads apis at this time, it's not nessesary for my prototyping purpose now.

But patches always welcome :)

=head1 FUNCTIONS

List of currently supported functions. Descriptions after function name are copied and pasted from uv.h

=head2 UV::run()

This function starts the event loop. It blocks until the reference count of the loop drops to zero. Always returns zero.

=head2 UV::run_once()

Poll for new events once. Note that this function blocks if there are no
pending events. Returns zero when done (no active handles or requests left),
or non-zero if more events are expected (meaning you should call
uv_run_once() again sometime in the future).

=head2 my $err = UV::last_error()

=head2 my $str_error = UV::strerror($err)

=head2 my $err_name = UV::err_name($err)

Most functions return boolean: 0 for success and -1 for failure.
On error the user should then call uv_last_error() to determine
the error code.

=head2 UV::shutdown($handle, $cb)

Shutdown the outgoing (write) side of a duplex stream. It waits for
pending write requests to complete. The handle should refer to a
initialized stream. req should be an uninitialized shutdown request
struct. The cb is called after shutdown is complete.

=head2 UV::is_active($handle)

Returns 1 if the prepare/check/idle/timer handle has been started, 0
otherwise. For other handle types this always returns 1.

=head2 UV::close($handle)

Request handle to be closed. This MUST be called on each handle before memory is released.

In-progress requests, like C<UV::connect> or C<UV::write>, are cancelled and
have their callbacks called asynchronously with status=-1 and the error code
set to C<UV::ECANCELED>.

=head2 UV::listen($stream, $backlog, $connection_cb)

=head2 UV::accept($server_stream, $client_stream)

This call is used in conjunction with `UV::listen` to accept incoming
connections. Call `UV::accept` after receiving a C<$connection_cb> to accept
the connection. Before calling C<UV::accept> use C<UV::*_init()> must be
called on the client. Non-zero return value indicates an error.

When the C<$connection_cb> is called it is guaranteed that C<UV::accept> will
complete successfully the first time. If you attempt to use it more than
once, it may fail. It is suggested to only call uv_accept once per
uv_connection_cb call.

=head2 UV::read_start($stream, $read_cb)

=head2 UV::read_stop($stream)

Read data from an incoming stream. The callback will be made several
several times until there is no more data to read or uv_read_stop is
called. When we've reached EOF nread will be set to -1 and the error is
set to UV_EOF. When nread == -1 the buf parameter might not point to a
valid buffer; in that case buf.len and buf.base are both set to 0.
Note that nread might also be 0, which does *not* indicate an error or
eof; it happens when libuv requested a buffer through the alloc callback
but then decided that it didn't need that buffer.

=head2 UV::read2_start($stream, $read2_cb)

Extended read methods for receiving handles over a pipe. The pipe must be
initialized with ipc == 1.

=head2 UV::write($stream, $buf)

=head2 UV::write($stream, $buf, $write_cb)

Write C<$buf> to stream.

=head2 UV::write2($stream, $buf, $send_stream)

=head2 UV::write2($stream, $buf, $send_stream, $write_cb)

Extended write function for sending handles over a pipe. The pipe must be
initialized with ipc == 1.
send_handle must be a TCP socket or pipe, which is a server or a connection
(listening or connected state).  Bound sockets or pipes will be assumed to
be servers.

=head2 UV::is_readable($stream)

=head2 UV::is_writeable($stream)

Used to determine whether a stream is readable or writable.

=head2 UV::is_closing($handle)

Used to determine whether a stream is closing or closed.

N.B. is only valid between the initialization of the handle
     and the arrival of the close callback, and cannot be used
     to validate the handle.

=head2 my $tcp_stream = UV::tcp_init()

Initialize tcp_stream object.

=head2 UV::tcp_nodelay($handle, $enable = 1)

Enable/disable Nagle's algorithm.

=head2 UV::tcp_keepalive($handle, $enable, $delay)

Enable/disable TCP keep-alive.

`ms` is the initial delay in seconds, ignored when `enable` is zero.

=head2 UV::tcp_simultaneous_accepts($handle, $enable)

This setting applies to Windows only.
Enable/disable simultaneous asynchronous accept requests that are
queued by the operating system when listening for new tcp connections.
This setting is used to tune a tcp server for the desired performance.
Having simultaneous accepts can significantly improve the rate of
accepting connections (which is why it is enabled by default).

=head2 UV::tcp_bind($handle, $ip, $port)

=head2 UV::tcp_bind6($handle, $ip, $port)

Bind tcp handles to $ip:$port

=head2 my ($ip, $port) = UV::tcp_getsockname($handle)

=head2 my ($ip, $port) = UV::tcp_getpeername($handle)

get tcp sockname or peername and return it as array.

=head2 UV::tcp_connect($handle, $ip, $port, $connect_cb)

=head2 UV::tcp_connect6($handle, $ip, $port, $connect_cb)

uv_tcp_connect, uv_tcp_connect6
These functions establish IPv4 and IPv6 TCP connections. Provide an
initialized TCP handle and an uninitialized uv_connect_t*. The callback
will be made when the connection is established.

=head2 my $udp = UV::udp_init()

Initialize a new UDP handle. The actual socket is created lazily.
Returns 0 on success.

=head2 UV::udp_bind($handle, $ip, $port, $flags = 0)

=head2 UV::udp_bind6($handle, $ip, $port, $flags = 0)

Bind to a IPv4/IPv6 address and port.

Arguments:
 handle    UDP handle. Should have been initialized with `uv_udp_init`.
 addr      struct sockaddr_in with the address and port to bind to.
 flags     Unused.

Returns:
 0 on success, -1 on error.

=head2 my ($ip, $port) = UV::udp_getsockname($handle)

get udp sockname and return it as array

=head2 UV::udp_set_membership($handle, $multicast_addr, $interface_addr, $membership)

Set membership for a multicast address

Arguments:
 handle              UDP handle. Should have been initialized with
                     `uv_udp_init`.
 multicast_addr      multicast address to set membership for
 interface_addr      interface address
 membership          Should be UV_JOIN_GROUP or UV_LEAVE_GROUP

Returns:
 0 on success, -1 on error.

=head2 UV::set_multicast_loop($handle, $on)

Set IP multicast loop flag. Makes multicast packets loop back to
local sockets.

Arguments:
 handle              UDP handle. Should have been initialized with
                     `uv_udp_init`.
 on                  1 for on, 0 for off

Returns:
 0 on success, -1 on error.

=head2 UV::set_multicast_ttl($handle, $ttl)

Set the multicast ttl

Arguments:
 handle              UDP handle. Should have been initialized with
                     `uv_udp_init`.
 ttl                 1 through 255

Returns:
 0 on success, -1 on error.

=head2 UV::udp_set_broadcast($handle, $on)

Set broadcast on or off

Arguments:
 handle              UDP handle. Should have been initialized with
                     `uv_udp_init`.
 on                  1 for on, 0 for off

Returns:
 0 on success, -1 on error.

=head2 UV::udp_set_ttl($handle, $ttl)

Set the time to live

Arguments:
 handle              UDP handle. Should have been initialized with
                     `uv_udp_init`.
 ttl                 1 through 255

Returns:
 0 on success, -1 on error.

=head2 UV::udp_send($handle, $buf, $ip, $port, $send_cb)

=head2 UV::udp_send6($handle, $buf, $ip, $port, $send_cb)

Send data. If the socket has not previously been bound with `uv_udp_bind`
or `uv_udp_bind6`, it is bound to 0.0.0.0 / ::0 (the "all interfaces" address)
and a random port number.

Arguments:
 handle    UDP handle. Should have been initialized with `uv_udp_init`.
 buf       buffer to send.
 ip        target ip
 port      target port
 send_cb   Callback to invoke when the data has been sent out.

Returns:
 0 on success, -1 on error.

=head2 UV::udp_recv_start($handle, $recv_cb)

Receive data. If the socket has not previously been bound with `uv_udp_bind`
or `uv_udp_bind6`, it is bound to 0.0.0.0 (the "all interfaces" address)
and a random port number.

Arguments:
 handle    UDP handle. Should have been initialized with `uv_udp_init`.
 recv_cb   Callback to invoke with received data.

Returns:
 0 on success, -1 on error.

=head2 UV::udp_recv_stop($handle)

Stop listening for incoming datagrams.

Arguments:
 handle    UDP handle. Should have been initialized with `uv_udp_init`.

Returns:
 0 on success, -1 on error.

=head2 my $tty = UV::tty_init($fd, $readable)

Initialize a new TTY stream with the given file descriptor. Usually the
file descriptor will be
  0 = stdin
  1 = stdout
  2 = stderr
The last argument, readable, specifies if you plan on calling
uv_read_start with this stream. stdin is readable, stdout is not.

TTY streams which are not readable have blocking writes.

=head2 UV::tty_set_mode($tty, $mode)

Set mode. 0 for normal, 1 for raw.

=head2 UV::tty_reset_mode()

To be called when the program exits. Resets TTY settings to default
values for the next process to take over.

=head2 my ($width, $height) = UV::tty_get_winsize($tty)

Gets the current Window size as array.

=head2 my $poll = UV::poll_init($fd)

Initialize the poll watcher using a file descriptor.

=head2 UV::poll_start($handle, $events, $poll_cb)

Starts polling the file descriptor. `events` is a bitmask consisting made up
of UV_READABLE and UV_WRITABLE. As soon as an event is detected the callback
will be called with `status` set to 0, and the detected events set en the
`events` field.

If an error happens while polling status may be set to -1 and the error
code can be retrieved with uv_last_error. The user should not close the
socket while uv_poll is active. If the user does that anyway, the callback
*may* be called reporting an error status, but this is not guaranteed.

Calling uv_poll_start on an uv_poll watcher that is already active is fine.
Doing so will update the events mask that is being watched for.

=head2 UV::poll_stop($handle)

Stops polling the file descriptor.

=head2 UV::guess_handle($fd)

Used to detect what type of stream should be used with a given file
descriptor. Usually this will be used during initialization to guess the
type of the stdio streams.
For isatty() functionality use this function and test for UV_TTY.

=head2 my $pipe = UV::pipe_init()

Initialize a pipe. The last argument is a boolean to indicate if
this pipe will be used for handle passing between processes.

=head2 UV::pipe_open($handle, $fd)

=head2 UV::pipd_bind($handle, $name)

=head2 UV::pipe_connect($handle, $name, $connect_cb)

Opens an existing file descriptor or HANDLE as a pipe.


=head2 my $prepare = UV::prepare_init()

=head2 UV::prepare_start($prepare, $prepare_cb)

=head2 UV::prepare_stop($prepare)

libev wrapper. Every active prepare handle gets its callback called
exactly once per loop iteration, just before the system blocks to wait
for completed i/o.

=head2 my $check = UV::check_init()

=head2 UV::check_start($check, $check_cb)

=head2 UV::check_stop($check)

libev wrapper. Every active check handle gets its callback called exactly
once per loop iteration, just after the system returns from blocking.

=head2 my $idle = UV::idle_init()

=head2 UV::idle_start($idle, $idle_cb)

=head2 UV::idle_stop($idle)

libev wrapper. Every active idle handle gets its callback called
repeatedly until it is stopped. This happens after all other types of
callbacks are processed.  When there are multiple "idle" handles active,
their callbacks are called in turn.

=head2 my $async = UV::async_init()

=head2 UV::async_send($async)

libev wrapper. uv_async_send wakes up the event
loop and calls the async handle's callback There is no guarantee that
every uv_async_send call leads to exactly one invocation of the callback;
The only guarantee is that the callback function is  called at least once
after the call to async_send. Unlike all other libuv functions,
uv_async_send can be called from another thread.

=head2 my $timer = UV::timer_init()

Create timer handle

=head2 UV::timer_start($timer, $timeout, $repeat, $timer_cb)

=head2 UV::timer_stop($timer)

Start the timer. `timeout` and `repeat` are in milliseconds.

If timeout is zero, the callback fires on the next tick of the event loop.

If repeat is non-zero, the callback fires first after timeout milliseconds
and then repeatedly after repeat milliseconds.

timeout and repeat are signed integers but that will change in a future
version of libuv. Don't pass in negative values, you'll get a nasty surprise
when that change becomes effective.

=head2 UV::timer_again($timer)

Stop the timer, and if it is repeating restart it using the repeat value
as the timeout. If the timer has never been started before it returns -1 and
sets the error to UV_EINVAL.

=head2 UV::timer_set_repeat($timer, $repeat)

=head2 UV::timer_get_repeat($timer)

Set the repeat value in milliseconds. Note that if the repeat value is set
from a timer callback it does not immediately take effect. If the timer was
non-repeating before, it will have been stopped. If it was repeating, then
the old repeat value will have been used to schedule the next timeout.

=head2 UV::getaddrinfo($node, $service, $getaddrinfo_cb, $hint = 0)

Asynchronous getaddrinfo(3).

Either node or service may be NULL but not both.

hints is a pointer to a struct addrinfo with additional address type
constraints, or NULL. Consult `man -s 3 getaddrinfo` for details.

Returns 0 on success, -1 on error. Call uv_last_error() to get the error.

If successful, your callback gets called sometime in the future with the
lookup result, which is either:

 a) status == 0, the res argument points to a valid struct addrinfo, or
 b) status == -1, the res argument is NULL.

On NXDOMAIN, the status code is -1 and uv_last_error() returns UV_ENOENT.

Call uv_freeaddrinfo() to free the addrinfo structure.

=head1 AUTHOR

Daisuke Murase <typester@cpan.org>

=cut
