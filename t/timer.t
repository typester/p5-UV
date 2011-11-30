use Test::More;

use_ok 'UV';

{
    my $one    = 0;
    my $repeat = 0;

    my $one_timer = UV::timer->new(10, 0, sub {
        $one++;
    });

    my $repeat_timer; $repeat_timer = UV::timer->new(10, 10, sub {
        $repeat++;

        if (5 == $repeat) {
            undef $repeat_timer;
        }
    });

    my $timeout_timer; $timeout_timer = UV::timer->new(100, 0, sub {
        undef $one_timer;
        undef $repeat_timer;
        undef $timeout_timer;
    });

    UV::run();

    is $one, 1, 'one shot timer ok';
    is $repeat, 5, 'repeat timer ok';
}

done_testing;
