use strict;
use warnings;
use Test::More;

use UV;

my $timer   = UV::timer_init();
my $counter = 0;

my $async; $async = UV::async_init(sub {
    UV::timer_stop($timer);
    UV::close($timer);
    UV::close($async);
});

UV::timer_start($timer, 100, 100, sub {
    $counter++;

    if (10 == $counter) {
        UV::async_send($async);
    }
});

UV::run;

is $counter, 10, 'async ok';

done_testing;
