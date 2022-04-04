"""E2E encryption in weechat"""
from mallumo.globalvars import *
from mallumo.config import init_config, shutdown
from mallumo.utils import iprnt
from mallumo.commands import command_cb
from mallumo.messages import message_in_cb, message_out_cb
from mallumo.statusbar import e2e_statusbar_cb

try:
    import weechat as wc

    if wc.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
                   SCRIPT_DESC, "shutdown", ""):
        init_config()

        iprnt("", "Installing PRIVMSG hooks")
        wc.hook_modifier("irc_in_privmsg", "message_in_cb", "")
        wc.hook_modifier("irc_out_privmsg", "message_out_cb", "")

        iprnt("", "Installing command hooks")
        wc.hook_command(
            SCRIPT_NAME, SCRIPT_HELP, "gen ||"
            "kex ||"
            "reset ||"
            "status ||"
            "enable ||"
            "disable ||", "", "", "command_cb", "")

        iprnt("", "Plugin initialized successfully")

except ModuleNotFoundError:
    pass
