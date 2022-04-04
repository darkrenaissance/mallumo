mallumo
=======

e2e encryption in weechat using libsodium.

![](screenshot.png)

## Dependencies

* `python-3.8` or newer.
* [`pynacl`](https://github.com/pyca/pynacl/)

N.B. I have only tested this on python3.10, but it should work with
others too.

## Installation

First clone the repo and symlink the python module into your weechat
autoload directory:

```shell
$ git clone https://github.com/darkrenaissance/mallumo
$ cd ~/.weechat/python
$ ln -s /path/to/mallumo/mallumo/ # Note this is the inner mallumo dir
$ ln -s $(realpath mallumo/__init__.py) autoload/mallumo.py
```

With this method, you can receive updates seamlessly, just by issuing
`git pull`.


## Usage

In weechat:

```
/help mallumo

[python/mallumo]  /mallumo  gen
                            kex
                            reset
                            status
                            enable
                            disable


E2E encryption for private IRC messages

Quick start:

Add an E2E item to the status bar by adding '[mallumo]' to the config setting
weechat.bar.status.items. This will show if your current chat is encrypted.

Usage:
/mallumo gen          [ generate a new keypair ]
/mallumo kex          [ initiate an e2e encrypted session ]
/mallumo reset [-f]   [ unset the public key associated to the current buffer ]
/mallumo status       [ show and possibly initialize a session ]
/mallumo disable      [ disable encryption for current buffer ]
/mallumo enable       [ enable encryption for current buffer ]
```

Before exiting, do run `/save` in order to make sure keep any pubkeys
you have exchanged.

## License

GNU GPL version 3
