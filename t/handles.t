use strict;
use warnings;
use Test::More;

use UV;

{
    my $handles = [];

    my $t1 = UV::timer_init();
    UV::timer_start($t1, 100, 0, sub {
        # do nothing
        UV::close($t1);
    });
    my $t2 = UV::timer_init();
    UV::timer_start($t2, 150, 0, sub {
        # do nothing
        UV::close($t2);
    });

    my $count_timer = UV::timer_init();
    UV::timer_start($count_timer, 60, 100, sub {
        push @$handles, UV::handles();
    });

    my $timeout_timer = UV::timer_init();
    UV::timer_start($timeout_timer, 200, 0, sub {
        UV::close($count_timer);
    });

    UV::run();

    is scalar(@{$handles}), 2;
    is scalar(@{$handles->[0]}), 4;
    is_deeply $handles->[0]->[0], { ref => 1, active => 1, type => UV::TIMER(), closing => 0 };
    is scalar(@{$handles->[1]}), 2;
    is_deeply $handles->[1]->[1], { ref => 1, active => 1, type => UV::TIMER(), closing => 0 };
}

done_testing;
