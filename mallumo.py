"""E2E encryption in weechat"""
from base64 import b64encode, b64decode
import shlex
import traceback

from nacl.public import PrivateKey, PublicKey, Box
import weechat as wc

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
/{SCRIPT_NAME} gen          [ generate a keypair ]
/{SCRIPT_NAME} kex          [ initiate an e2e encrypted session ]
/{SCRIPT_NAME} reset [-f]   [ unset the public key associated to the current buffer ]
/{SCRIPT_NAME} status       [ show session status ]
"""

# Here we'll keep all the NaCl boxes in memory for quick access.
SODIUM_BOXES = {}

# These are our weechat configuration sections
CONFIG_SECTIONS = {}

# Configuration file
CONFIG_FILE = None

# These bytes can't be in a protocol message
IRC_SANITIZE_TABLE = dict((ord(char), None) for char in "\r\n\x00")


def prnt(buf, msg):
    """Print a message to a given buffer"""
    wc.prnt(buf, f"{SCRIPT_NAME}: {msg}")


def eprnt(buf, msg):
    """Print an error message to a given buffer"""
    wc.prnt(buf, f"{wc.prefix('error')}{SCRIPT_NAME}: {msg}")


def config_prefix(option):
    """Set up a prefix for config lookup"""
    return f"{SCRIPT_NAME}.{option}"


def config_get_prefixed(option):
    """Get a config value prepended with our prefix"""
    return wc.config_get(config_prefix(option))


def config_string(option):
    """Get a string config value prepended with our prefix"""
    return wc.config_string(config_get_prefixed(option))


def debug(msg):
    """Debugging facility"""
    debug_option = config_get_prefixed("general.debug")
    if not wc.config_boolean(debug_option):
        return

    debug_buffer = wc.buffer_search("python", f"{SCRIPT_NAME} debug")
    if not debug_buffer:
        debug_buffer = wc.buffer_new(f"{SCRIPT_NAME} debug", "", "", "", "")
        wc.buffer_set(debug_buffer, "title", f"{SCRIPT_NAME} debug")
        wc.buffer_set(debug_buffer, "localvar_set_no_log", "1")

    prnt(debug_buffer, f"debug:\t{msg}")


def buffer_is_private(buf):
    """Check whether given buffer is a private chat"""
    return wc.buffer_get_string(buf, "localvar_type") == "private"


def irc_user(nick, server):
    """Format an identifier given nickname and server"""
    return f"{nick.lower()}@{server}"


def e2e_statusbar_cb(data, item, window):
    """Callback for statusbar item changes"""
    if window:
        buf = wc.window_get_pointer(window, "buffer")
    else:
        # If the bar item is in a root bar that is not in a window, window
        # will be empty.
        buf = wc.current_buffer()

    if not buffer_is_private(buf):
        return ""

    peer = irc_user(
        wc.buffer_get_string(buf, "localvar_channel"),
        wc.buffer_get_string(buf, "localvar_server"),
    )

    bar_parts = []

    box = SODIUM_BOXES.get(peer)

    if box:
        bar_parts.append("".join(
            [wc.color("green"), "SEC",
             wc.color("default")]))
    else:
        bar_parts.append("".join(
            [wc.color("lightred"), "!SEC",
             wc.color("default")]))

    result = "".join(bar_parts)
    if result:
        result = f"{wc.color('default')}E2E:{result}"

    if box:
        wc.buffer_set(buf, "localvar_set_e2e_encrypted", "true")
    else:
        wc.buffer_set(buf, "localvar_set_e2e_encrypted", "false")

    return result


def isupport_value(server, feature):
    """Check server supports features"""
    args = f"{server},{feature}"
    return wc.info_get("irc_server_isupport_value", args)


def is_a_channel(channel, server):
    """Check if we're in a channel"""
    prefixes = \
        tuple(isupport_value(server, "CHANTYPES")) + \
        tuple(isupport_value(server, "STATUSMSG"))

    if not prefixes:
        prefixes = ("#", "&", "+", "!", "@")

    return channel.startswith(prefixes)


class PrivmsgParseException(Exception):
    """Pass exception if we fail to parse a privmsg"""


def parse_privmsg(message, server):
    """Parse a privmsg"""
    wc_result = wc.info_get_hashtable("irc_message_parse",
                                      dict(message=message))

    if wc_result["command"].upper() == "PRIVMSG":
        target, text = wc_result["arguments"].split(" ", 1)
        if text.startswith(":"):
            text = text[1:]

        result = {
            "from": wc_result["host"],
            "to": target,
            "text": text,
        }

        if wc_result["host"]:
            result["from_nick"] = wc_result["nick"]
        else:
            result["from_nick"] = ""

        if is_a_channel(target, server):
            result["to_channel"] = target
            result["to_nick"] = None
        else:
            result["to_channel"] = None
            result["to_nick"] = target

        return result

    raise PrivmsgParseException(message)


def command(buf, command_str):
    """Wrapper around weechat.command"""
    debug(command_str)
    wc.command(buf, command_str)


def irc_sanitize(msg):
    """Sanitize IRC input"""
    return str(msg).translate(IRC_SANITIZE_TABLE)


def privmsg(server, nick, message):
    """Send privmsgs"""
    for line in message.splitlines():
        srv = irc_sanitize(server)
        nik = irc_sanitize(nick)
        lin = irc_sanitize(line)
        command("", f"/quote -server {srv} PRIVMSG {nik} :{lin}")


def msg_is_kex(msg):
    """Check if message is for key exchange"""
    return (msg.startswith("?e2e_kexreq:") or msg.startswith("?e2e_kexrep:")
            ) and msg.endswith("?") and len(msg) == 57


def message_in_cb(data, modifier, modifier_data, string):
    """Incoming messages callback"""
    debug(("message_in_cb", data, modifier, modifier_data, string))

    parsed = parse_privmsg(string, modifier_data)
    debug(("parsed message", parsed))

    # If we're in a channel, do nothing more
    if parsed["to_channel"]:
        return string

    server = modifier_data

    # Here we implement commands that might come to us.
    msg = parsed["text"]

    # Key exchange request/reply
    if msg_is_kex(msg):
        encoded_pubkey = msg[12:-1]
        # Try parsing the public key
        try:
            their_pubkey = PublicKey(b64decode(encoded_pubkey))
        except:
            # Just do nothing
            return string

        # At this point we got a valid pubkey. Let's write it down, in case
        # we didn't have it already.
        nick = irc_user(parsed["from_nick"], server)
        if not wc.config_is_set_plugin(f"pubkey_{nick}"):
            wc.config_set_plugin(f"pubkey_{nick}", encoded_pubkey)

        # If we didn't set up our keypair, we'll also stay silent.
        encoded_secret = config_string("general.secret")
        if encoded_secret == "":
            eprnt("", "You have not created an e2e keypair. Try /mallumo gen")
            return string

        our_secret = PrivateKey(b64decode(encoded_secret))
        our_pubkey = b64encode(our_secret.public_key.encode()).decode()

        # Otherwise, reply with our pubkey to complete the key exchange.
        if msg.startswith("?e2e_kexreq:"):
            privmsg(server, parsed["from_nick"], f"?e2e_kexrep:{our_pubkey}?")

        # And finally, set up a Box.
        SODIUM_BOXES[nick] = Box(our_secret, their_pubkey)

        # Make it green!
        wc.bar_item_update(SCRIPT_NAME)
        return string

    if msg.startswith("?e2e_msg:") and msg.endswith("?"):
        # An encrypted message, let's try to decrypt it.
        encoded_text = msg[9:-1]

        # Do we have a box?
        nick = irc_user(parsed["from_nick"], server)
        box = SODIUM_BOXES.get(nick)
        if not box:
            if not wc.config_is_set_plugin(f"pubkey_{nick}"):
                eprnt("", f"{nick} tried to send you an encrypted message")
                eprnt("", "But we could not find their public key.")
                eprnt("", "Try to do key exchange first with /mallumo kex")
                return string

            encoded_pubkey = wc.config_get_plugin(f"pubkey_{nick}")
            their_pubkey = PublicKey(b64decode(encoded_pubkey))

            encoded_secret = config_string("general.secret")
            if encoded_secret == "":
                eprnt("", f"{nick} tried to send you an encrypted message")
                eprnt("", "But we don't have a secret key set up!")
                eprnt("", "You have to set up a secret key with /mallumo gen")
                return string

            our_secret = PrivateKey(b64decode(encoded_secret))
            SODIUM_BOXES[nick] = Box(our_secret, their_pubkey)
            box = SODIUM_BOXES.get(nick)

        # Try to decrypt the message
        try:
            plaintext = box.decrypt(b64decode(encoded_text))
        except:
            eprnt("", f"Failed decrypting message from {nick}")
            return string

        return string.replace(msg, plaintext.decode())

    nick = irc_user(parsed["from_nick"], server)
    if SODIUM_BOXES.get(nick):
        # Prepend a warning if we have an initialized box, but got an
        # unencrypted message.
        return string.replace(msg, f"[!SEC] {msg}")

    return string


def message_out_cb(data, modifier, modifier_data, string):
    """Outgoing messages callback"""
    result = ""

    # If any exception is raised in this function, weechat will not send
    # the outgoing message, which could be something that the user intended
    # to be encrypted. This paranoid exception handling ensures that the
    # system fails closed and not open.
    try:
        debug(("message_out_cb", data, modifier, modifier_data, string))

        parsed = parse_privmsg(string, modifier_data)
        debug(("parsed_message", parsed))

        if parsed["to_channel"]:
            return string

        # Try encrypting the message
        server = modifier_data

        # Do we have a box?
        nick = irc_user(parsed["to"], server)
        box = SODIUM_BOXES.get(nick)
        if not box:
            if not wc.config_is_set_plugin(f"pubkey_{nick}"):
                eprnt("", f"{nick} tried to send you an encrypted message")
                eprnt("", "But we could not find their public key.")
                eprnt("", "Try to do key exchange first with /mallumo kex")
                return string

            encoded_pubkey = wc.config_get_plugin(f"pubkey_{nick}")
            their_pubkey = PublicKey(b64decode(encoded_pubkey))

            encoded_secret = config_string("general.secret")
            if encoded_secret == "":
                eprnt("", f"{nick} tried to send you an encrypted message")
                eprnt("", "But we don't have a secret key set up!")
                eprnt("", "You have to set up a secret key with /mallumo gen")
                return string

            our_secret = PrivateKey(b64decode(encoded_secret))
            SODIUM_BOXES[nick] = Box(our_secret, their_pubkey)
            box = SODIUM_BOXES.get(nick)

        # In case we're replying to kex
        if parsed["text"].startswith("?e2e_kexrep:"):
            return string

        encrypted = box.encrypt(parsed["text"].encode())
        encrypted_encoded = b64encode(encrypted).decode()
        privmsg(server, parsed["to"], f"?e2e_msg:{encrypted_encoded}?")

    except:
        try:
            eprnt("", traceback.format_exc())
        except:
            pass

    return result


def command_cb(data, buf, args):
    """mallumo commands"""
    result = wc.WEECHAT_RC_ERROR

    if not buffer_is_private(buf):
        eprnt(buf, "These commands can only be ran in a private buffer")
        return result

    arg_parts = shlex.split(args)

    if arg_parts[0] == "gen":
        prnt(buf, "========================================================")
        prnt(buf, "Generating a keypair...")
        secret = PrivateKey.generate()
        public = secret.public_key
        secret_e = b64encode(secret.encode()).decode()
        public_e = b64encode(public.encode()).decode()
        prnt(buf, f"Secret: {secret_e}")
        prnt(buf, f"Public: {public_e}")
        prnt(buf, "")
        prnt(buf, "Set this secret key with the following command:")
        prnt(buf, f'/set {SCRIPT_NAME}.general.secret "{secret_e}"')
        prnt(buf, "========================================================")
        return wc.WEECHAT_RC_OK

    if arg_parts[0] == "kex":
        encoded_secret = config_string("general.secret")
        if encoded_secret == "":
            eprnt(buf, "You do not have a keypair set up.")
            eprnt(buf, f'Run "/{SCRIPT_NAME} gen" to create one')
            return result

        nick, server = (wc.buffer_get_string(buf, "localvar_channel"),
                        wc.buffer_get_string(buf, "localvar_server"))
        user = irc_user(nick, server)

        encoded_pubkey = wc.config_get_plugin(f"pubkey_{user}")
        if encoded_pubkey != "":
            eprnt(buf, "This user already has a key set up.")
            eprnt(buf, "If you want to change it, you have to unset it first:")
            eprnt(buf, f"/{SCRIPT_NAME} reset")
            return result

        secret = PrivateKey(b64decode(encoded_secret))
        public = b64encode(secret.public_key.encode()).decode()

        privmsg(server, nick, f"?e2e_kexreq:{public}?")
        return wc.WEECHAT_RC_OK

    if arg_parts[0] == "reset":
        if len(arg_parts) < 2 or arg_parts[1] != "-f":
            eprnt(buf, f"Use `/{SCRIPT_NAME} reset -f` to actually do this.")
            return result

        nick = irc_user(wc.buffer_get_string(buf, "localvar_channel"),
                        wc.buffer_get_string(buf, "localvar_server"))

        command("", f"/unset plugins.var.python.{SCRIPT_NAME}.pubkey_{nick}")
        prnt(buf, f"Public key for {nick} has been unset.")
        return wc.WEECHAT_RC_OK

    if arg_parts[0] == "status":
        nick = irc_user(wc.buffer_get_string(buf, "localvar_channel"),
                        wc.buffer_get_string(buf, "localvar_server"))

        status = {
            "initialized": False,
            "has_pubkey": False,
            "has_secret": False,
        }

        encoded_secret = config_string("general.secret")
        if encoded_secret != "":
            status["has_secret"] = True

        encoded_pubkey = wc.config_get_plugin(f"pubkey_{nick}")
        if encoded_pubkey != "":
            status["has_pubkey"] = True

        box = SODIUM_BOXES.get(nick)
        if box:
            status["initialized"] = True

        prnt(buf, "====================================================")
        prnt(buf, "E2E Status:")
        if status["initialized"]:
            prnt(buf, f"{wc.color('green')}Initialized{wc.color('default')}")
            prnt(buf, f"Box secret: {b64encode(box.shared_key()).decode()}")
        else:
            eprnt(buf, f"{wc.color('red')}Uninitialized{wc.color('default')}")
            prnt(buf, "Box secret: Not initialized")

        if status["has_pubkey"]:
            prnt(buf, f"{nick} pubkey: {encoded_pubkey}")
        else:
            eprnt(buf, f"{nick} pubkey: Not found")

        if status["has_secret"]:
            secret = PrivateKey(b64decode(encoded_secret))
            pubkey = b64encode(secret.public_key.encode()).decode()
            prnt(buf, f"own pubkey: {pubkey}")
        else:
            eprnt(buf, "own pubkey: Not initialized")

        prnt(buf, "====================================================")

        if not status["initialized"] and (status["has_pubkey"] and \
            status["has_secret"]):
            # However we have enough things to initiate the encryption.
            pubkey = PublicKey(b64decode(encoded_pubkey))
            box = Box(secret, pubkey)
            SODIUM_BOXES[nick] = box
            prnt(buf, "We managed to instantiate a box now...")
            prnt(buf, "Further messages should be e2e encrypted")
            wc.bar_item_update(SCRIPT_NAME)

    return result


def free_all_config():
    """Free config items that were set"""
    for section in CONFIG_SECTIONS.values():
        wc.config_section_free_options(section)
        wc.config_section_free(section)

    wc.config_free(CONFIG_FILE)


def shutdown():
    """Teardown"""
    wc.config_write(CONFIG_FILE)
    free_all_config()
    wc.bar_item_remove(E2E_STATUSBAR)
    return wc.WEECHAT_RC_OK


if wc.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
               SCRIPT_DESC, "shutdown", ""):
    prnt("", "Plugin registered successfully!")

    CONFIG_FILE = wc.config_new(SCRIPT_NAME, "", "")

    CONFIG_SECTIONS["general"] = wc.config_new_section(CONFIG_FILE, "general",
                                                       0, 0, "", "", "", "",
                                                       "", "", "", "", "", "")

    for opt, typ, description, default in [
        ("debug", "boolean", "script debugging", "on"),
        ("secret", "string", "secret key (base64)", ""),
    ]:
        wc.config_new_option(CONFIG_FILE, CONFIG_SECTIONS["general"], opt, typ,
                             description, "", 0, 0, default, default, 0, "",
                             "", "", "", "", "")

    wc.config_read(CONFIG_FILE)

    wc.hook_modifier("irc_in_privmsg", "message_in_cb", "")
    wc.hook_modifier("irc_out_privmsg", "message_out_cb", "")

    wc.hook_command(SCRIPT_NAME, SCRIPT_HELP, "gen ||"
                    "kex ||"
                    "reset ||"
                    "status ||", "", "", "command_cb", "")

    E2E_STATUSBAR = wc.bar_item_new(SCRIPT_NAME, "e2e_statusbar_cb", "")
    wc.bar_item_update(SCRIPT_NAME)

    prnt("", "Plugin initialized successfully!")
