use strict;
use warnings;
use Test::More;

use UV;

{
    my $n = 0;

    my $idle = UV::idle_init();
    UV::idle_start($idle, sub {
        $n++;
        UV::close($idle);
    });

    UV::run();

    is $n, 1, 'one shot idle ok';
}

done_testing;
