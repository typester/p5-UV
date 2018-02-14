use strict;
use warnings;
use lib '.';

BEGIN {
    my @devmods = qw(
        Module::Install::ReadmeFromPod
        Module::Install::Repository
        Module::Install::XSUtil
    );
    my @not_available;

    {
        $|=1; # ref RT #115206
        local *STDOUT;
        eval qq{use inc::Module::Install; 1;} or push @not_available, 'inc::Module::Install';
    }

    for my $mod (@devmods) {
        eval qq{require $mod} or push @not_available, $mod;
    }
    if (@not_available) {
        print qq{# The following modules are not available.\n};
        print qq{# `$^X $0 | cpanm` will install them:\n};
        print $_, "\n" for @not_available;
        print "\n";
        exit -1;
    }
}

use inc::Module::Install;
$Module::Install::AUTHOR = 0 if $ENV{TRAVIS};

name 'UV';
all_from 'lib/UV.pm';
readme_from 'lib/UV.pm';

use_ppport 3.20;
cc_src_paths 'src';
cc_include_paths 'deps/libuv/include';
cc_warnings;

test_requires 'Test::TCP';

no_index directory => 'deps';

auto_set_repository;

if ($^O eq 'linux') {
    cc_libs 'm', 'dl', 'rt', 'pthread';
}
elsif ($^O eq 'darwin') {
    cc_libs 'm', 'pthread';
    makemaker_args->{dynamic_lib} = {
        OTHERLDFLAGS => '-framework CoreServices',
    }
}
elsif ($^O =~ /^(gnuk)?freebsd$/ || $^O eq 'netbsd' || $^O eq 'openbsd') {
    cc_libs 'm', 'kvm', 'pthread';
}
elsif ($^O eq 'sunos' || $^O eq 'solaris') {
    cc_libs 'm', 'kstat', 'nsl', 'sendfile', 'socket', 'pthreads';
}
elsif ($^O eq 'MSWin32') {
    cc_append_to_ccflags '-D_WIN32_WINNT=0x600'; # https://github.com/joyent/libuv/issues/263
    cc_libs 'm', 'ws2_32', 'psapi', 'iphlpapi', 'kernel32';
}
else {
    die "$^O is unsupported at this point\n";
}

unless ($^O eq 'MSWin32') {
    cc_append_to_ccflags '-fPIC';

    # XXX
    use File::Spec;
    my $mk_file = File::Spec->catfile('deps', 'libuv', 'config-unix.mk');

    open my $fh, '<', $mk_file or die $!;
    my $mk = do { local $/; <$fh> };
    close $fh;

    unless ($mk =~ /-g -fPIC/) {
        $mk =~ s/-g/-g -fPIC/;

        open $fh, '>', $mk_file or die $!;
        print $fh $mk;
        close $fh;
    }
}

makemaker_args->{MYEXTLIB} = 'deps/libuv/libuv$(LIB_EXT)';

{
    package MY;
    sub postamble {
        <<'__EOF__';
$(MYEXTLIB):
	$(MAKE) -C deps/libuv
__EOF__
    }
}

WriteAll;
