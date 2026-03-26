# modern-replicator

Recently reminded of the good 'ol Gentoo days, I long for a transparent caching
proxy.  This is in the spirit of http-replicator, without the async complexity
and so far hasn't livelocked on me.

* Only does static file mode
* Combines running downloads
* Server SSL support (tested with easy-rsa root)
* Works with pacman, pip, uv, and requests
* Able to saturate 1Gbps with SSL on both client/server using 20% of a core.
* Only tested on Linux with btrfs
* Cancelled downloads will continue on server

TODO

* Drop privs after bind (or otherwise support 443)
* Range support
* Resume support
* Configuration, click command line
* Last-modified support (primarily for pacman)
* Revalidate some files (primarily for pacman db)
* Stats page (hit rate, in-progress requests)

# Version Compat

This library is compatile with Python 3.10+, but should be linted under the
newest stable version.

# Versioning

This library follows [meanver](https://meanver.org/) which basically means
[semver](https://semver.org/) along with a promise to rename when the major
version changes.

# License

modern-replicator is copyright [Tim Hatch](https://timhatch.com/), and licensed under
the MIT license.  See the `LICENSE` file for details.
