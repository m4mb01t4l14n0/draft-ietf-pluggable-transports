# draft-ietf-pluggable-transports
Working document for IETF Internet Draft "Pluggable Transports"

## Tooling to build the drafts
You have to install kramdown-rfc2629. 

[`kramdown-rfc2629`](https://github.com/cabo/kramdown-rfc2629) requires
[Ruby](https://www.ruby-lang.org/) and can be installed using the Ruby package
manager, `gem`:

```sh
$ gem install kramdown-rfc2629
```

(These instructions taken from https://github.com/martinthomson/i-d-template/blob/master/doc/SETUP.md#kramdown-rfc2629

## Building the Drafts

Formatted text and HTML versions of the drafts can be built using `make`.

```sh
$ make
```

This requires that you have the necessary software installed.  See
[the instructions](https://github.com/martinthomson/i-d-template/blob/master/doc/SETUP.md).
