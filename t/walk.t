use strict;
use warnings;
use Test::More;

use UV;

{
    my $loop = UV::default_loop();
    isa_ok $loop, 'UV::loop';

    my @handle_list = ();

    my $t1 = UV::timer_init();
    UV::timer_start($t1, 100, 0, sub {
        # do nothing;
    });
    my $t2 = UV::timer_init();
    UV::timer_start($t2, 150, 0, sub {
        # do nothing;
    });
    my $checker = UV::timer_init();
    UV::timer_start($checker, 50, 0, sub {
        UV::walk(sub {
            my $h = shift;
            push @handle_list, $h;
        });
    });

    my $closer = UV::timer_init();
    UV::timer_start($closer, 80, 0, sub {
    });

    UV::run();

    is scalar(@handle_list), 4;
    is $handle_list[0]->type, UV::TIMER;
    is $handle_list[1]->type, UV::TIMER;
    is $handle_list[2]->type, UV::TIMER;
    is $handle_list[3]->type, UV::TIMER;

    UV::close($checker);
    UV::close($t1);
    UV::close($t2);
    UV::close($closer);
}

done_testing;
