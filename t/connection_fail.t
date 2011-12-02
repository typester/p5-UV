use strict;
use warnings;
use Test::More;
use Test::TCP;

use_ok 'UV';

my ($tcp, $timer);
my $connect_cb_calls = 0;
my $timer_cb_calls = 0;

{
    $tcp = UV::tcp_init();

    my $r = UV::tcp_connect($tcp, '127.0.0.1', empty_port(), sub {
        my ($status) = @_;

        is $status, -1, 'error status ok';
        is UV::last_error(), UV::ECONNREFUSED(), 'ECONNREFUSED ok';

        $connect_cb_calls++;

        UV::close($tcp);
    });

    UV::run();

    is $connect_cb_calls, 1, 'connect_cb_calls ok';
}

$connect_cb_calls = 0;

{
    $timer = UV::timer_init();
    $tcp   = UV::tcp_init();

    UV::tcp_connect($tcp, '127.0.0.1', empty_port(), sub {
        my ($status) = @_;

        is $status, -1, 'error status ok';
        is UV::last_error(), UV::ECONNREFUSED(), 'ECONNREFUSED ok';

        $connect_cb_calls++;

        UV::timer_start($timer, 100, 0, sub {
            $timer_cb_calls++;

            is $connect_cb_calls, 1;

            UV::close($tcp);
            UV::close($timer);
        });
    });

    UV::run();

    is $connect_cb_calls, 1;
}

done_testing;
