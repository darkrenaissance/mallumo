"""Global variables to pass around"""

SCRIPT_NAME = "mallumo"
SCRIPT_AUTHOR = "Ivan Jelincic <parazyd@dyne.org>"
SCRIPT_LICENSE = "GPL3"
SCRIPT_VERSION = "0.1"
SCRIPT_DESC = "E2E encryption for private IRC messages"
SCRIPT_HELP = f"""{SCRIPT_DESC}

Quick start:

Add an E2E item to the status bar by adding '[mallumo]' to the config setting
weechat.bar.status.items. This will show if your current chat is encrypted.

Usage:
/{SCRIPT_NAME} gen          [ generate a new keypair ]
/{SCRIPT_NAME} kex          [ initiate an e2e encrypted session ]
/{SCRIPT_NAME} reset [-f]   [ unset the public key associated to the current buffer ]
/{SCRIPT_NAME} status       [ show and possibly initialize a session ]
/{SCRIPT_NAME} disable      [ disable encryption for current buffer ]
/{SCRIPT_NAME} enable       [ enable encryption for current buffer ]
"""

# Here we'll keep all the NaCl boxes in memory for quick access.
SODIUM_BOXES = {}

# These are our weechat configuration sections
CONFIG_SECTIONS = {}

# Configuration file
CONFIG_FILE = None

# These bytes can't be in a protocol message
IRC_SANITIZE_TABLE = dict((ord(char), None) for char in "\r\n\x00")

# Statusbar item
E2E_STATUSBAR = None
