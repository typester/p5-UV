use strict;
use warnings;

BEGIN {
    my @devmods = qw(
        Module::Install::ReadmeFromPod
        Module::Install::Repository
        Module::Install::XSUtil
    );
    my @not_available;

    {
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
    cc_libs 'm', 'rt', 'pthread';
}
elsif ($^O eq 'darwin') {
    cc_libs 'm', 'pthread';
    makemaker_args->{dynamic_lib} = {
        OTHERLDFLAGS => '-framework CoreServices',
    }
}
elsif ($^O =~ /^(gnuk)?freebsd$/ || $^O eq 'netbsd' || $^O eq 'openbsd') {
    cc_libs 'm', 'pthread';
}
elsif ($^O eq 'sunos' || $^O eq 'solaris') {
    cc_libs 'm', 'socket', 'nsl', 'kstat', 'pthreads';
}
elsif ($^O eq 'MSWin32') {
    cc_libs 'm', 'ws2_32';
}
else {
    die "$^O is unsupported at this point\n";
}

makemaker_args->{MYEXTLIB} = 'deps/libuv/uv$(LIB_EXT)';

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
