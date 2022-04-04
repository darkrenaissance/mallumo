mallumo
=======

e2e encryption in weechat using libsodium.

## Dependencies

* `python-3.8` or newer.
* [`pynacl`](https://github.com/pyca/pynacl/)

N.B. I have only tested this on python3.10, but it should work with
others too.

## Installation

First clone the repo and symlink the python module into your weechat
directory:

```shell
$ git clone https://github.com/darkrenaissance/mallumo
$ ln -s $(realpath mallumo/mallumo.py) ~/.weechat/python
```

With this method, you can receive updates seamlessly, just by issuing
`git pull`.


## Usage

In weechat:

```
/mallumo help

[python/mallumo]  /mallumo  gen
                            kex
                            reset
                            status

E2E encryption for private IRC messages

Quick start:

Add an E2E item to the status bar by adding '[mallumo]' to the config setting
weechat.bar.status.items. This will show if your current chat is encrypted.

Usage:
/mallumo gen          [ generate a keypair ]
/mallumo kex          [ initiate an e2e encrypted session ]
/mallumo reset [-f]   [ unset the public key associated to the current buffer ]
/mallumo status       [ show session status ]
```

## License

GNU GPL version 3
