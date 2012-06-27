use strict;
use warnings;
use Test::More;
use Test::TCP;

use IO::Socket::INET;
use Socket qw/IPPROTO_TCP TCP_NODELAY SOCK_STREAM/;

use UV;

test_tcp(
    server => sub {
        my ($port) = @_;

        my $server = UV::tcp_init();
        UV::tcp_bind($server, '0.0.0.0', $port);
        UV::listen($server, 128, sub {
            my $client = UV::tcp_init();
            UV::accept($server, $client);

            UV::read_start($client, sub {
                my ($nread, $buf) = @_;

                if ($nread > 0) {
                    UV::write($client, $buf);
                }
            });
        });
        UV::run;
    },

    client => sub {
        my ($port, $server_pid) = @_;

        my $sock = IO::Socket::INET->new(
            PeerHost => '127.0.0.1',
            PeerPort => $port,
            Blocking => 0,
        );

        my $poll = UV::poll_init(fileno $sock);
        UV::poll_start($poll, UV::WRITABLE, sub {
            my ($status, $events) = @_;

            is $events, UV::WRITABLE, 'connected ok';

            syswrite $sock, 'hi!';

            UV::poll_stop($poll);
            UV::poll_start($poll, UV::READABLE, sub {
                my ($status, $events) = @_;

                is $events, UV::READABLE, 'data ready ok';

                my $r = sysread $sock, my $buf, 1024;
                is $r, 3, 'read once ok';

                is $buf, 'hi!', 'echo ok';

                UV::poll_stop($poll);
                UV::close($poll);
            });

        });

        UV::run;
    },
);


done_testing;
