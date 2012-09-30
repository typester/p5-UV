package UV;
use strict;
use XSLoader;

our $VERSION = '0.1';

XSLoader::load __PACKAGE__, $VERSION;

use constant READABLE => 1;
use constant WRITABLE => 2;

1;

__END__

=head1 NAME

UV - perl interface to libuv

=head1 SYNOPSIS

=head1 DESCRIPTION

=head1 FUNCTIONS

=head2 UV::run()

=head2 UV::version()

=head1 AUTHOR

Daisuke Murase <typester@cpan.org>

=cut
