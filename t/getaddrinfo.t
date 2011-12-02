use strict;
use warnings;
use Test::More;

use_ok 'UV';

{
    # basic
    my $getaddrinfo_cbs = 0;

    UV::getaddrinfo("localhost", undef, sub {
        $getaddrinfo_cbs++;
    });

    UV::run();

    is $getaddrinfo_cbs, 1, "getaddrinfo_cbs ok";
}

{
    # concurrent
    my @callback_counts;

    for (my $i = 0; $i < 10; $i++) {
        my $v = $i;
        $callback_counts[$i] = 0;

        my $r = UV::getaddrinfo("localhost", undef, sub {
            $callback_counts[$v]++;
        });

        is $r, 0, 'getaddrinfo res ok';
    }

    UV::run();

    for (my $i = 0; $i < 10; $i++) {
        is $callback_counts[$i], 1, "count $i ok";
    }
}

done_testing;
