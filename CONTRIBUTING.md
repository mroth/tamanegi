Please read the entire README before working on a PR.  In particular,
familiarize yourself with the intentions of this project and ask if you feel it
it within the spirit of the project.

Only well documented code will be accepted.  Please consider this repository
as much a learning resource as source code, for others who wish to understand
how `.onion` names are brute forced.

For now, that means as much as possible I am avoiding any third-party libraries
(believe me, this is painful given how bad the `flag` package is in Go) because
package management is a unresolved story in Go, and avoiding using OpenSSL
bindings (which would almost certainly speed things up) because it complicates
the compilation significantly for end-users.†  

†: I will consider PRs that do otherwise, but please have a very strong reason
for doing so and be prepared to discuss it.
