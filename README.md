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
