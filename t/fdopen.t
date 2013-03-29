use strict;
use warnings;
use Test::More;
use Test::TCP;

plan tests => 2;

use UV;
use IO::Socket::INET;

my $port = empty_port;

my $sock = IO::Socket::INET->new(
        LocalPort => $port,
        Type      => SOCK_STREAM,
        Blocking  => 0,
        ReuseAddr => 1,
        Listen    => 10,
    ) or die $!;

my $tcp = UV::tcp_init;
UV::tcp_open($tcp, fileno($sock));
UV::listen($tcp, 10, sub {
    my $con = UV::tcp_init();
    UV::accept($tcp, $con);
    UV::read_start($con, sub {
        my ($nread, $buf) = @_;

        is $nread, 5;
        is $buf, 'hello';

        UV::stop;
    });
});

my $client = UV::tcp_init;
UV::tcp_connect($client, '127.0.0.1', $port, sub {
    UV::write($client, "hello");
});

UV::run;
