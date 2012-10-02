use strict;
use warnings;
use Test::More;

use UV;

my $tcp = UV::tcp_init();
isa_ok $tcp, 'UV::handle';
is $tcp->type, UV::TCP, 'tcp type ok';

my $udp = UV::udp_init();
isa_ok $udp, 'UV::handle';
is $udp->type, UV::UDP, 'udp type ok';

my $tty = UV::tty_init(fileno(STDOUT), 0);
isa_ok $tty, 'UV::handle';
is $tty->type, UV::TTY, 'tty type ok';

my $poll = UV::poll_init(fileno(STDOUT));
isa_ok $poll, 'UV::handle';
is $poll->type, UV::POLL, 'poll type ok';

my $pipe = UV::pipe_init(0);
isa_ok $pipe, 'UV::handle';
is $pipe->type, UV::NAMED_PIPE, 'pipe type ok';

my $prepare = UV::prepare_init();
isa_ok $prepare, 'UV::handle';
is $prepare->type, UV::PREPARE, 'prepare type ok';

my $check = UV::check_init();
isa_ok $check, 'UV::handle';
is $check->type, UV::_CHECK, 'check type ok';

my $idle = UV::idle_init();
isa_ok $idle, 'UV::handle';
is $idle->type, UV::IDLE, 'idle type ok';

my $async = UV::async_init(sub {});
isa_ok $async, 'UV::handle';
is $async->type, UV::ASYNC, 'async type ok';

my $timer = UV::timer_init();
isa_ok $timer, 'UV::handle';
is $timer->type, UV::TIMER, 'timer type ok';

done_testing;
