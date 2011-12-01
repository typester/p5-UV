use strict;
use warnings;
use Getopt::Long;

GetOptions(
    \my %option,
    qw/port=i/
);
$option{port} ||= 3000;

use UV;

my $server = UV::tcp_init();
UV::tcp_bind($server, '0.0.0.0', $option{port})
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

print "Listening 0.0.0.0:$option{port}\n";
UV::run();
