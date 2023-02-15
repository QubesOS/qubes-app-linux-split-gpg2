# split-gpg2

## About split-gpg2

This software allows you to separate the handling of private key material from the rest of GnuPG's processing.
This is similar to how smartcards work, except that in this case the handling of the private key is not put into some small microcontroller but into another Qubes domain.

Since GnuPG 2.1.0, secret keys are handled by `gpg-agent`.
This allows to split `gpg` (the cmdline tool, which handles public keys and the actual OpenPGP protocol) and `gpg-agent` (which handles the private keys).
This software implements this for Qubes.
This mainly consists of a restrictive filter in front of `gpg-agent`, written in a memory safe language (Python).

The server is the domain which runs the (real) `gpg-agent` and has access to your private key material.
The client is the domain in which you run `gpg` and which accesses the server via Qubes RPC.

The server domain is generally considered more trusted then the client domain.
This implies that the response from the server is _not_ sanitized.


## Requirements

 - Python 3.5 or newer
 - GnuPG 2.1 or newer

## Building

Add it as a component to [qubes-builder](https://www.qubes-os.org/doc/qubes-builder/) and built it.

For development you can also build the Debian packet in tree.
Just run `dpkg-buildpackage -us -uc` at the top level.

## Installation

Install the deb or the rpm on your TemplateVM(s).


## Configuration

Create/Edit `/etc/qubes/policy.d/30-user-gpg2.policy` in dom0, and add a line like this:

```
qubes.Gpg2 + gpg-client-vm @default allow target=gpg-server-vm
```

Import/Generate your secret keys in the server domain.
For example:

```
gpg-server-vm$ gpg --import /path/to/my/secret-keys-export
gpg-server-vm$ gpg --import-ownertrust /path/to/my/ownertrust-export
```
or

```
gpg-server-vm$ gpg --gen-key
```

In dom0 enable the `split-gpg2-client` service in the client domain, for example via the command-line:

```shell
dom0$ qvm-service <SPLIT_GPG2_CLIENT_DOMAIN_NAME> split-gpg2-client on
```

To verify if this was done correctly:

```shell
dom0$ qvm-service <SPLIT_GPG2_CLIENT_DOMAIN_NAME>
```

Output should be:

```shell
split-gpg2-client on
```

Restart the client domain.

Export the **public** part of your keys and import them in the client domain.
Also import/set proper "ownertrust" values.
For example:

```
gpg-server-vm$ gpg --export > public-keys-export
gpg-server-vm$ gpg --export-ownertrust > ownertrust-export
gpg-server-vm$ qvm-copy public-keys-export ownertrust-export

gpg-client-vm$ gpg --import ~/QubesIncoming/gpg-server-vm/public-keys-export
gpg-client-vm$ gpg --import-ownertrust ~/QubesIncoming/gpg-server-vm/ownertrust-export
```

This should be enough to have it running:
```
gpg-client-vm$ gpg -K
/home/user/.gnupg/pubring.kbx
-----------------------------
sec#  rsa2048 2019-12-18 [SC] [expires: 2021-12-17]
      50C2035AF57B98CD6E4010F1B808E4BB07BA9EFB
uid           [ultimate] test
ssb#  rsa2048 2019-12-18 [E]
```

If you want change some server option copy `/usr/share/doc/split-gpg2/examples/split-gpg2-rc.example` to `~/.config/split-gpg2-rc` and change it as desired.

If you have a passphrase on your keys and `gpg-agent` only shows the "keygrip" (something like the fingerprint of the private key) when asking for the passphrase, then make sure that you have imported the public key part in the server domain.

## Advanced usage

There are a few option not described in this README.
See the comments in the example config and the source code.

Similar to a smartcard, split-gpg2 only tries to protect the private key.
For advanced usages, consider if a specialized RPC service would be better.
It could do things like checking what data is singed, detailed logging, exposing the encrypted content only to a VM without network, etc.

## Allow key generation

By setting `SPLIT_GPG2_ALLOW_KEYGEN=yes` in `split-gpg2-rc` you can allow the client to generate new keys.
Normal usage should not need this.

**Warning**: This feature is new and not much tested.
Therefore it's not security supported!

## Copyright

Copyright (C) 2014 HW42 <hw42@ipsumj.de>\
Copyright (C) 2019 Marek Marczykowski-Górecki <marmarek@invisiblethingslab.com>

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
