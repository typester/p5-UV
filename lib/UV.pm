package UV;
use strict;
use XSLoader;

our $VERSION = '0.1';

XSLoader::load __PACKAGE__, $VERSION;

sub timer {
    UV::timer->new(@_);
}

1;

__END__

=head1 NAME

UV - perl interface to libuv

=head1 SYNOPSIS

use UV;

my $t; $t = UV::timer 1000, 1000, sub {
    # repeatable timer
};

UV::run;

=head1 DESCRIPTION

=head1 FUNCTIONS

=head2 UV::timer($timeout, $repeat, $cb)

=head2 UV::run()

=head2 UV::version()

return libuv version.

=head1 AUTHOR

Daisuke Murase <typester@cpan.org>

=cut
