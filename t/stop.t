use strict;
use warnings;
use Test::More;

use UV;

my $udp = UV::udp_init();
UV::udp_recv_start($udp, sub {
    # block
});

my $timer_fired;
my $timer = UV::timer_init();
UV::timer_start($timer, 100, 0, sub {
    $timer_fired++;
    UV::stop;
});

UV::run;

is $timer_fired, 1;

done_testing;
