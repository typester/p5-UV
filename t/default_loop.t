use strict;
use warnings;
use Test::More;

use UV;

my $loop = UV::default_loop();
isa_ok $loop, 'UV::loop';

is $loop->active_handles, 0, '0 active_handles ok';

my $run_timer = 0;

my $timer = UV::timer_init();
UV::timer_start($timer, 100, 500, sub {
    $run_timer++;

    is $loop->active_handles, 1, '1 active_handles ok';

    UV::timer_stop($timer);
    UV::close($timer);
});

UV::run;

ok $run_timer, 'timer run ok';
is $loop->active_handles, 0, '0 active_handles again ok';

done_testing;
