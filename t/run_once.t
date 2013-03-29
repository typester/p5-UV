use strict;
use warnings;
use Test::More;

use UV;

my $counter = 0;
my $idle    = UV::idle_init();

UV::idle_start($idle, sub {
    $counter++;
});
for my $i (1..10) {
    UV::run(UV::RUN_ONCE);
    is $counter, $i, "counter increments as expected";
}

done_testing;
