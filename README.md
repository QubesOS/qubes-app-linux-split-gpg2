# split-gpg2

## About split-gpg2

This software allows you to separate the handling of private key material from the rest of GnuPG's processing.
This is similar to how smartcards work, except that in this case the handling of the private key is not put into some small microcontroller but into another Qubes domain.
It can also be used to allow GnuPG to use keys stored on a smartcard that is not attached to the qube.

Since GnuPG 2.1.0, secret keys are handled by `gpg-agent`.
This allows to split `gpg` (the cmdline tool, which handles public keys and the actual OpenPGP protocol) and `gpg-agent` (which handles the private keys).
This software implements this for Qubes.
This mainly consists of a restrictive filter in front of `gpg-agent`, written in a memory safe language (Python).

The server is the domain which runs the (real) `gpg-agent` and has access to your private key material, or to the smartcard that has the private key material.
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

> [!NOTE]
> * Ensure your key doesn't have a password set.
> * Ensure you have subkeys for signing and, if needed, encryption.

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

If you want change some server option copy `/usr/share/doc/split-gpg2/examples/qubes-split-gpg2.conf.example` to `~/.config/qubes-split-gpg2/qubes-split-gpg2.conf` and change it as desired, it will take precedence over other loaded files, such as the drop-in configuration files with the suffix `.conf` in `~/.config/qubes-split-gpg2/conf.d/`.

If you have a passphrase on your keys and `gpg-agent` only shows the "keygrip" (something like the fingerprint of the private key) when asking for the passphrase, then make sure that you have imported the public key part in the server domain.

## Subkeys vs primary keys

split-gpg2 only knows a hash of the data being signed.
Therefore, it cannot differentiate between e.g. signatures of a piece of data or signatures of another key.
This means that a client can use split-gpg2 to sign other keys, which split-gpg1 did not allow.

To prevent this, split-gpg2 creates a new GnuPG home directory and imports the secret subkeys (**not** the primary key!) to it.
Clients will be able to use the secret parts of the subkeys, but not of the primary key.
If your primary key is able to sign data and certify other keys, and your only subkey can only perform encryption, this means that all signing will fail.
To make signing work again, generate a subkey that is capable of signing but **not** certification.
split-gpg2 does not generate this key for you, so you need to generate it yourself.
If you want to generate a key in software, use the `addkey` command of `gpg2 --edit-key`.
If you want to generate a key on a smartcard or other hardware token, use `addcardkey` instead.

## Advanced usage

There are a few option not described in this README.
See the comments in the example config and the source code.

Similar to a smartcard, split-gpg2 only tries to protect the private key.
For advanced usages, consider if a specialized RPC service would be better.
It could do things like checking what data is singed, detailed logging, exposing the encrypted content only to a VM without network, etc.

Using split-gpg2 as the "backend" for split-gpg1 is known to work.

## Allow key generation

By setting `allow_keygen = yes` in `qubes-split-gpg2.conf` you can allow the client to generate new keys.
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
