use strict;
use warnings;
use UV;

my $port = $ARGV[0] || 0;

my $server = UV::tcp_init();
UV::tcp_bind($server, '0.0.0.0', $port) and die UV::strerror(UV::last_error());
UV::listen($server, 128, sub {
    my $client = UV::tcp_init();
    UV::accept($server, $client) and die UV::strerror(UV::last_error());

    UV::read_start($client, sub {
        my ($nread, $buf) = @_;

        if ($nread < 0) {
            my $err = UV::last_error();
            if ($err != UV::EOF) {
                warn UV::strerror($err);
            }
            UV::close($client);
        }
        elsif ($nread > 0) {
            UV::write($client, $buf);
        }
    });

}) and die UV::strerror(UV::last_error());

UV::run();
