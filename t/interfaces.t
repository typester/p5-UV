use strict;
use warnings;
use Test::More;

use UV;

my $addr = UV::interface_addresses;

is ref $addr, 'ARRAY';

my $first = $addr->[0];
ok exists $first->{name};
ok exists $first->{is_internal};
ok exists $first->{address4};
ok exists $first->{address6};

done_testing;
