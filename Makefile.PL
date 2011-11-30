use inc::Module::Install;

name 'UV';
all_from 'lib/UV.pm';

use_ppport 3.19;
cc_src_paths 'src';
cc_include_paths 'deps/libuv/include';
cc_warnings;


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
$(MYEXTLIB): deps/libuv/Makefile
	cd deps/libuv && $(MAKE)
__EOF__
    }
}

WriteAll;
