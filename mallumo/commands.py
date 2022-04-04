"""Mallumo commands"""
import shlex
from base64 import b64encode, b64decode

from nacl.public import PrivateKey, PublicKey, Box
import weechat as wc

from mallumo.globalvars import SCRIPT_NAME, SODIUM_BOXES
from mallumo.utils import (buffer_is_private, prnt, iprnt, eprnt, irc_user,
                           config_string, privmsg, command)


def generate_keypair(buf):
    """Generate a new random keypair and print info to the given buffer"""
    prnt(buf, "===========================================================")
    iprnt(buf, "Generating a keypair...")

    secret = PrivateKey.generate()
    public = secret.public_key

    e_public = b64encode(public.encode()).decode()
    e_secret = b64encode(secret.encode()).decode()

    iprnt(buf, f"Public key: {e_public}")
    iprnt(buf, f"Secret key: {e_secret}")
    iprnt(buf, "")
    iprnt(buf, "Set this secret key with the following command:")
    iprnt(buf, f'/set {SCRIPT_NAME}.general.secret "{e_secret}"')
    prnt(buf, "===========================================================")


def initiate_key_exchange(buf):
    """Initiate key exchange with the other side of the private buffer"""
    encoded_secret = config_string("general.secret")
    if encoded_secret == "":
        eprnt(buf, "You do not have a keypair set up.")
        eprnt(buf, f'Run "/{SCRIPT_NAME} gen" to create one')
        return wc.WEECHAT_RC_ERROR

    nick, server = (wc.buffer_get_string(buf, "localvar_channel"),
                    wc.buffer_get_string(buf, "localvar_server"))

    ident = irc_user(nick, server)

    encoded_pubkey = wc.config_get_plugin(f"pubkey_{ident}")
    if encoded_pubkey != "":
        eprnt(buf, "We seem to already know about a key from this user.")
        eprnt(buf, "If you want to change it, you have to unset it first:")
        eprnt(buf, f"/{SCRIPT_NAME} reset")
        return wc.WEECHAT_RC_ERROR

    our_secret = PrivateKey(b64decode(encoded_secret))
    our_public = b64encode(our_secret.public_key.encode()).decode()

    privmsg(server, nick, f"?e2e_kexreq:{our_public}?")
    return wc.WEECHAT_RC_OK


def reset_session(buf):
    """Reset an e2e session with the other side of the private buffer"""
    ident = irc_user(wc.buffer_get_string(buf, "localvar_channel"),
                     wc.buffer_get_string(buf, "localvar_server"))

    command("", f"/unset plugins.var.python.{SCRIPT_NAME}.pubkey_{ident}")
    iprnt(buf, f"Public key for {ident} has been unset.")

    SODIUM_BOXES.pop(ident)
    iprnt(buf, f"Box for {ident} has been burned.")


def session_status(buf):
    """Query the session status of the current private buffer and potentially
    initialize a dormant session if we know their key"""
    ident = irc_user(wc.buffer_get_string(buf, "localvar_channel"),
                     wc.buffer_get_string(buf, "localvar_server"))

    encoded_secret = config_string("general.secret")
    has_secret = encoded_secret != ""

    encoded_pubkey = wc.config_get_plugin(f"pubkey_{ident}")
    has_pubkey = encoded_pubkey != ""

    box = SODIUM_BOXES.get(ident)
    is_initialized = box is not None

    prnt(buf, "===========================================================")
    if is_initialized:
        init_status = f"{wc.color('green')}initialized{wc.color('default')}"
        box_secret = f"{b64encode(box.shared_key()).decode()}"
    else:
        init_status = f"{wc.color('red')}uninitialized{wc.color('default')}"
        box_secret = f"{wc.color('orange')}not found{wc.color('default')}"

    if has_pubkey:
        known_pub = f"{encoded_pubkey}"
    else:
        known_pub = f"{wc.color('orange')}not found{wc.color('default')}"

    if has_secret:
        _secret = PrivateKey(b64decode(encoded_secret))
        our_pub = b64encode(_secret.public_key.encode()).decode()
    else:
        our_pub = f"{wc.color('lightred')}not set up{wc.color('default')}"

    iprnt(buf, f"E2E Status: {init_status}")
    iprnt(buf, f"Box secret: {box_secret}")
    iprnt(buf, f"Known pubkey: {known_pub}")
    iprnt(buf, f"Our pubkey: {our_pub}")
    prnt(buf, "===========================================================")

    # Check if we have enough data to initialize a session
    if not is_initialized and (has_pubkey and has_secret):
        iprnt(buf, "We have enough data to initialize a session...")
        pubkey = PublicKey(b64decode(encoded_pubkey))
        box = Box(_secret, pubkey)
        SODIUM_BOXES[ident] = box
        iprnt(buf, "We managed to instantiate a box now.")
        iprnt(buf, "Further messages should be e2e encrypted")
        wc.bar_item_update(SCRIPT_NAME)


def enable_encryption(buf):
    """Enable encryption for current buffer"""
    ident = irc_user(wc.buffer_get_string(buf, "localvar_channel"),
                     wc.buffer_get_string(buf, "localvar_server"))

    command("", f"/unset plugins.var.python.{SCRIPT_NAME}.disable_{ident}")
    iprnt(buf, "Encryption has been enabled for this buffer")
    iprnt(buf, f"Run /{SCRIPT_NAME} status to see the state")


def disable_encryption(buf):
    """Disable encryption for current buffer"""
    ident = irc_user(wc.buffer_get_string(buf, "localvar_channel"),
                     wc.buffer_get_string(buf, "localvar_server"))

    wc.config_set_plugin(f"disable_{ident}", "1")
    iprnt(buf, "Encryption has been disbaled for this buffer. Sad.")
    iprnt(buf, f"Run /{SCRIPT_NAME} enable to bring it back")


def command_cb(data, buf, args):
    """Central callback for mallumo commands"""
    arg_parts = shlex.split(args)
    if len(arg_parts) == 0:
        return wc.WEECHAT_RC_ERROR

    if arg_parts[0] == "gen":
        generate_keypair(buf)
        return wc.WEECHAT_RC_OK

    # The following commands are only supposed to run in private buffers, so
    # we check and enforce this:
    if not buffer_is_private(buf):
        eprnt(buf, "This command can only be ran in a private buffer")
        return wc.WEECHAT_RC_ERROR

    if arg_parts[0] == "kex":
        return initiate_key_exchange(buf)

    if arg_parts[0] == "reset":
        if len(arg_parts) < 2 or arg_parts[1] != "-f":
            eprnt(buf, f'Use "/{SCRIPT_NAME} reset -f" to actually do this.')
            return wc.WEECHAT_RC_ERROR

        reset_session(buf)
        return wc.WEECHAT_RC_OK

    if arg_parts[0] == "status":
        session_status(buf)
        return wc.WEECHAT_RC_OK

    if arg_parts[0] == "enable":
        enable_encryption(buf)
        return wc.WEECHAT_RC_OK

    if arg_parts[0] == "disable":
        disable_encryption(buf)
        return wc.WEECHAT_RC_OK

    return wc.WEECHAT_RC_ERROR
