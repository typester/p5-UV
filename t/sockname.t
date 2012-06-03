use strict;
use warnings;
use Test::More;
use Test::TCP;

use UV;

my $port = empty_port();

my $server = UV::tcp_init();
UV::tcp_bind($server, '0.0.0.0', $port);
UV::listen($server, 128, sub {
    my $client = UV::tcp_init();
    my $r = UV::accept($server, $client);
    is $r, 0, 'accept ok';

    my ($host, $port) = UV::tcp_getpeername($client);
    is $host, '127.0.0.1';

    UV::close($server);
});

my ($host, $tcp_port) = UV::tcp_getsockname($server);

is $host, '0.0.0.0';
is $tcp_port, $port;

my $client = UV::tcp_init();
UV::tcp_connect($client, "127.0.0.1", $port, sub {
    my ($host, $tcp_port) = UV::tcp_getpeername($client);
    is $host, '127.0.0.1';
    is $tcp_port, $port;
});

UV::run;

done_testing;
