"""Message callbacks and cryptography"""
import json
import traceback
from base64 import b64decode, b64encode

import weechat as wc
from nacl.public import PublicKey, PrivateKey, Box

from mallumo.globalvars import SCRIPT_NAME, SODIUM_BOXES
from mallumo.utils import (debug, is_a_channel, eprnt, privmsg, irc_user,
                           config_string)


def msg_is_kex(msg):
    """Check if message is related to key exchange"""
    return (msg.startswith("?e2e_kexreq:") or msg.startswith("?e2e_kexrep:")
            ) and msg.endswith("?") and len(msg) == 57


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


def message_in_cb(data, modifier, modifier_data, string):
    """Incoming messages callback"""
    debug(("message_in_cb()", data, modifier, modifier_data, string))

    parsed = parse_privmsg(string.encode(), modifier_data)
    debug(json.dumps(parsed))

    # If we're in a channel, do nothing more
    if parsed["to_channel"]:
        return string

    # Now we check if we're getting keys or encrypted messages
    server = modifier_data
    ident = irc_user(parsed["from_nick"], server)
    msg = parsed["text"]

    # Key exchange request/reply
    if msg_is_kex(msg):
        encoded_pubkey = msg[msg.find(":") + 1:-1]
        # Try parsing the public key
        try:
            recv_pubkey = PublicKey(b64decode(encoded_pubkey))
        except:
            # Just do nothing
            return string

        # At this point we got a valid pubkey. Let's write it down, in case
        # we didn't have it already.
        if not wc.config_is_set_plugin(f"pubkey_{ident}"):
            wc.config_set_plugin(f"pubkey_{ident}", encoded_pubkey)
        else:
            eprnt("", f"{ident} gave us a key different than the one we know")
            eprnt("", "It's possible to reset the session if needed using:")
            eprnt("", f"/{SCRIPT_NAME} reset")

        # If we didn't set up our keypair, we stay silent.
        encoded_secret = config_string("general.secret")
        if encoded_secret == "":
            eprnt("", f"{ident} requested key exchange, but we have no keys")
            eprnt("", f"Use /{SCRIPT_NAME} gen to create one")
            return string

        our_secret = PrivateKey(b64decode(encoded_secret))
        our_pubkey = b64encode(our_secret.public_key.encode()).decode()

        # Otherwise, we reply with our pubkey to complete the key exchange.
        if msg.startswith("?e2e_kexreq:"):
            privmsg(server, parsed["from_nick"], f"?e2e_kexrep:{our_pubkey}?")

        # And finally, set up a Box.
        SODIUM_BOXES[ident] = Box(our_secret, recv_pubkey)

        # Make it green!
        wc.bar_item_update(SCRIPT_NAME)
        return string

    # An encrypted message, let's try to decrypt it.
    if msg.startswith("?e2e_msg:") and msg.endswith("?"):
        encoded_text = msg[msg.find(":") + 1:-1]

        # Do we have a box?
        box = SODIUM_BOXES.get(ident)

        if not box:
            if not wc.config_is_set_plugin(f"pubkey_{ident}"):
                eprnt("", f"{ident} tried to send an encrypted message.")
                eprnt("", "But we could not find their public key.")
                eprnt("", f"Try to exchange keys with /${SCRIPT_NAME} kex")
                return string

            # Instantiate a box since we seem to have a public key match
            encoded_pubkey = wc.config_get_plugin(f"pubkey_{ident}")
            their_pubkey = PublicKey(b64decode(encoded_pubkey))

            encoded_secret = config_string("general.secret")
            if encoded_secret == "":
                eprnt("", f"{ident} tried to send an encrypted message.")
                eprnt("", "But we don't have a secret key set up.")
                eprnt("", f"Create one with /${SCRIPT_NAME} gen")
                eprnt("", f"And then exchange keys with /${SCRIPT_NAME} kex")
                return string

            our_secret = PrivateKey(b64decode(encoded_secret))
            SODIUM_BOXES[ident] = Box(our_secret, their_pubkey)
            box = SODIUM_BOXES.get(ident)

        # Try to decrypt the message
        try:
            plaintext = box.decrypt(b64decode(encoded_text))
        except:
            eprnt("", f"Failed decrypting message from {ident}")
            return string

        return string.replace(msg, plaintext.decode())

    if SODIUM_BOXES.get(ident):
        # Prepend a warning if we have an instantiated box, but got an
        # unencrypted message.
        return string.replace(msg, f"[Unencrypted message] {msg}")

    # If nothing happened, just pass the message through
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
        debug(json.dumps(parsed))

        # Skip processing messages to public channels
        if parsed["to_channel"]:
            return string

        server = modifier_data
        ident = irc_user(parsed["to"], server)

        # And also if we've forcefully disabled encryption. Sad.
        if wc.config_is_set_plugin(f"disable_{ident}"):
            return string

        # In case we're replying to kex
        if msg_is_kex(parsed["text"]):
            return string

        buf = wc.current_buffer()

        # Try encrypting the message
        box = SODIUM_BOXES.get(ident)
        if not box:
            if not wc.config_is_set_plugin(f"pubkey_{ident}"):
                eprnt(buf, "We tried to send an encrypted message")
                eprnt(buf, "But we could not find the recipient's pubkey")
                eprnt(buf, f"Try to exchange keys with /{SCRIPT_NAME} kex")
                eprnt(buf, f"Or disable encryption: /{SCRIPT_NAME} disable")
                raise Exception("No recipient pubkey")

            encoded_pubkey = wc.config_get_plugin(f"pubkey_{ident}")
            their_pubkey = PublicKey(b64decode(encoded_pubkey))

            encoded_secret = config_string("general.secret")
            if encoded_secret == "":
                eprnt(buf, "We tried to send an encrypted message")
                eprnt(buf, "But we don't have a secret key set up.")
                eprnt(buf, f"Create one with /${SCRIPT_NAME} gen")
                eprnt(buf, f"And then exchange keys with /${SCRIPT_NAME} kex")
                eprnt(buf, f"Or disable encryption: /{SCRIPT_NAME} disable")
                raise Exception("No secret key")

            our_secret = PrivateKey(b64decode(encoded_secret))
            SODIUM_BOXES[ident] = Box(our_secret, their_pubkey)
            box = SODIUM_BOXES.get(ident)

        encrypted = box.encrypt(parsed["text"].encode())
        encrypted_encoded = b64encode(encrypted).decode()
        privmsg(server, parsed["to"], f"?e2e_msg:{encrypted_encoded}?")

    except:
        try:
            eprnt("", traceback.format_exc())
            eprnt(buf, "Failed sending message. See core buffer for trace.")
        except:
            pass

    return result
