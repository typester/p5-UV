use strict;
use warnings;
use Test::More;

use_ok 'UV';

my $r;

my $tcp_server = UV::tcp_init();
$r = UV::tcp_bind($tcp_server, '0.0.0.0', 9999);
is $r, 0, 'bind ok';

UV::listen($tcp_server, 10, sub {
    my $con = UV::tcp_init();

    $r = UV::accept($tcp_server, $con);
    is $r, 0, 'accept ok';

    UV::read_start($con, sub {
        my ($nread, $buf) = @_;

        is $buf, 'ping', 'ping receive ok';

        UV::write($con, 'pong', sub {
            UV::close($con);
            UV::close($tcp_server);
        });
    });
});

my $tcp_client = UV::tcp_init();
UV::tcp_connect($tcp_client, "127.0.0.1", 9999, sub {
    my ($status) = @_;

    is $status, 0, "connect ok";

    UV::write($tcp_client, 'ping');
    UV::read_start($tcp_client, sub {
        my ($nread, $buf) = @_;
        is $buf, 'pong', 'pong receive ok';

        UV::close($tcp_client);
    });
});

UV::run();

done_testing;
