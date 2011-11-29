use inc::Module::Install;

name 'UV';
all_from 'lib/UV.pm';

use_ppport 3.19;
cc_src_paths 'src';
cc_include_paths 'deps/libuv/include';
cc_warnings;

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
