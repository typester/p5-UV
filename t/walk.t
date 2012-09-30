use strict;
use warnings;
use Test::More;

use UV;

{
    my $counts1 = 0;
    my $counts2 = 0;

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

    use Data::Dumper;

    my $count_timer1 = UV::timer_init();
    UV::timer_start($count_timer1, 60, 0, sub {
        UV::walk(sub{ $counts1 += 1; });
        UV::close($count_timer1);
    });
    my $count_timer2 = UV::timer_init();
    UV::timer_start($count_timer2, 120, 0, sub {
        UV::walk(sub{ $counts2 += 1; });
        UV::close($count_timer2);
    });

    UV::run();

    is $counts1, 4; # t1, t2, count_timer1, count_timer2
    is $counts2, 2; # t2, count_timer2
}

done_testing;
