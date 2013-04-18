milter-dnsbl
============

A sendmail milter that uses blacklists

http://blog.postmaster.gr/2007/07/26/milter-dnsbl/

Sendmail administrators using FEATURE(dnsbl) may have noticed that ruleset
check_rcpt is executed after all connected milters have executed the
corresponding xxfi_*() routines.

Wouldn’t it be better if a milter (in fact the first in order) could block a
connection based on a list of DNSBLs?

That is why I wrote my first milter, milter-dnsbl. It has no configuration
file; on startup it takes a number of arguments that allow you to specify a
number of DNSBLs, plus whitelists published via DNS, or based on the domain
name of the connecting host. It requires a running lwresd(8) which it uses as
a caching server. Read the manpage that comes with the source code distribution.

milter-dnsbl is distributed with an OpenBSD-style license and has been tested
on an Ubuntu 6.06 i386 server.
