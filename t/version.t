use strict;
use warnings;
use Test::More;

use UV;

my $version     = UV::version;
my $version_str = UV::version_string;

my $major = $version >> 16 & 0xff;
my $minor = $version >> 8 & 0xff;
my $patch = $version & 0xff;

my ($v1, $v2, $v3) = split /\./, $version_str;

is $major, $v1;
is $minor, $v2;
is $patch, $v3;

is $version_str, '0.10.2';

done_testing
