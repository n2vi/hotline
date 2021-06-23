# hotline
modern analog of the classic Moscow - Washington hotline

There is interest around the world in security of nuclear crisis
communications, a hotline that could be used by national leaders to avoid
misunderstandings that lead to war.
https://soundcloud.com/securityandtechnology/security-through-simplicity

The files here are a proof-of-concept exploration of just how
small we can make such a system. This is still a long way from
a product ready for real-world use, but does contain working
code that has actually exchanged a few messages. It is mainly
intended to provide a basis for discussing possible approaches
to then be more professionally created by an international
technical team.

* hotline cryptography.pdf - puck-to-puck protocol
* hotline networking.pdf - puck-to-ROCCS protocol
* puck.go - end device message handling
* puckfs.go - network app for puck and ROCCS
* ascon.go - lightweight crypto for puckfs.go 

-----

Our project includes both a technology effort to build a crisis
communication system and a diplomatic effort to deploy it to reduce the
chance of accidental nuclear war. We believe CATALINK should be strictly
reserved for use by National Command Authorities at the level of leader of
government and official backup leaders in any chain of succession. There
are many layers of authority in any nuclear armed state, but in times of
crisis any uncertainty about who speaks authoritatively for the country
would undermine and negate the entire concept.  Indeed, it is extremely
unlikely that nuclear armed states would agree to the necessary key
exchanges to make the system work unless it was so restricted.

That said, the software and hardware and network designs included in this
repository are published under the extremely permissive 0BSD license,
which allows anyone to use this material for any purpose. You may even
create a company based on it and not pay us any royalties or get any
permission. We hope you won't use it for any nefarious purpose---and
given the key distribution method you would be well advised not to if
you are trying to avoid attention from law enforcement---but the choice
is yours. Without the keys created by, and shared between, the nuclear
national command authorities, systems based on the designs could not be
connected to CATALINK."
