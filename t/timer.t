use strict;
use warnings;
use Test::More;

use_ok 'UV';

{
    my $one    = 0;
    my $repeat = 0;

    my $one_timer = UV::timer_init();
    UV::timer_start($one_timer, 10, 0, sub {
        $one++;
    });

    my $repeat_timer = UV::timer_init();
    UV::timer_start($repeat_timer, 10, 10, sub {
        $repeat++;

        if (5 == $repeat) {
            UV::timer_stop($repeat_timer);
        }
    });

    my $timeout_timer = UV::timer_init();
    UV::timer_start($timeout_timer, 100, 0, sub {
        UV::close($one_timer);
        UV::close($repeat_timer);
        UV::close($timeout_timer);
    });

    UV::run();

    is $one, 1, 'one shot timer ok';
    is $repeat, 5, 'repeat timer ok';
}

done_testing;
