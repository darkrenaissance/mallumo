"""Weechat tility functions"""
import weechat as wc

from mallumo.globalvars import SCRIPT_NAME, IRC_SANITIZE_TABLE


def prnt(buf, msg):
    """Print a message to the given buffer"""
    wc.prnt(buf, f"{SCRIPT_NAME}: {msg}")


def iprnt(buf, msg):
    """Print an informational message to the given buffer"""
    wc.prnt(buf, f"{wc.prefix('network')}{SCRIPT_NAME}: {msg}")


def eprnt(buf, msg):
    """Print an error message to the given buffer"""
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

    prnt(debug_buffer, f"debug: {msg}")


def buffer_is_private(buf):
    """Check whether given buffer is a private chat"""
    return wc.buffer_get_string(buf, "localvar_type") == "private"


def irc_user(nick, server):
    """Format an internal identifier given a nickname and server"""
    return f"{nick.lower()}@{server}"


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
