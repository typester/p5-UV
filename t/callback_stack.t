use strict;
use warnings;
use Test::More;
use Test::TCP;
use FindBin;

use UV;

my $testport = empty_port();

my $nested = 0;

my $MESSAGE = 'Failure is for the weak. Everyone dies alone.';

my $connect_cb_called  = 0;
my $write_cb_called    = 0;
my $timer_cb_called    = 0;
my $bytes_received     = 0;
my $shutdown_cb_called = 0;

# echo server
my $pid = fork;
if (!defined $pid) {
    die 'fork failed';
}
elsif (0 == $pid) {
    exec $^X, "$FindBin::Bin/echo_server.pl", $testport;
}
else {
    END { kill 9, $pid };
}

my ($client, $timer);

my $shutdown_cb = sub {
    my ($status) = @_;

    is $status, 0, 'shutdown status ok';
    is $nested, 0, 'shutdown_cb must be called from a fresh stack ok';

    $shutdown_cb_called++;
};

my $read_cb = sub {
    my ($nread, $buf) = @_;

    if ($nread == 0) {
        is UV::last_error(), UV::EAGAIN(), 'err is EAGAIN ok';
        return;
    }
    elsif ($nread == -1) {
        is UV::last_error(), UV::EOF(), 'eof ok';

        $nested++;
        UV::close($client);
        $nested--;

        return;
    }

    $bytes_received += $nread;

    if ($bytes_received == length $MESSAGE) {
        $nested++;
        UV::shutdown($client, $shutdown_cb) and die 'uv_shutdown failed';
        $nested--;
    }
};

my $timer_cb = sub {
    my ($status) = @_;

    is $status, 0, 'timer status ok';
    is $nested, 0, 'timer_cb must be called from a fresh stack ok';

    $nested++;

    UV::read_start($client, $read_cb);

    $nested--;

    $timer_cb_called++;

    UV::close($timer);
};

my $write_cb = sub {
    my ($status) = @_;

    is $status, 0, 'write status ok';
    is $nested, 0, 'write_cb must be called from a fresh stack ok';

    $nested++;

    $timer = UV::timer_init();
    UV::timer_start($timer, 500, 0, $timer_cb);

    $nested--;

    $write_cb_called++;
};

my $connect_cb = sub {
    my ($status) = @_;

    is $status, 0, 'connect status ok';
    is $nested, 0, 'connect_cb must be called from a fresh stack ok';

    $nested++;

    UV::write($client, $MESSAGE, $write_cb) and die 'uv_write failed';

    $nested--;

    $connect_cb_called++;
};

sleep 1; # wait for server

$client = UV::tcp_init();

$nested++;

if (UV::tcp_connect($client, '127.0.0.1', $testport, $connect_cb)) {
    die 'uv_tcp_connect failed';
}
$nested--;

UV::run();

is $nested, 0, 'nested ok';
is $connect_cb_called, 1, 'connect_cb must be called exactly once ok';
is $write_cb_called, 1, 'write_cb must be called exactly once ok';
is $timer_cb_called, 1, 'timer_cb must be called exactly once ok';
is $bytes_received, length $MESSAGE, 'bytes_received ok';
is $shutdown_cb_called, 1, 'shutdown_cb must be called exactly once ok';

done_testing;
