"""Statusbar functionality"""
import weechat as wc

from mallumo.globalvars import SODIUM_BOXES
from mallumo.utils import buffer_is_private, irc_user


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

    nick = irc_user(
        wc.buffer_get_string(buf, "localvar_channel"),
        wc.buffer_get_string(buf, "localvar_server"),
    )

    sbar = []

    box = SODIUM_BOXES.get(nick)
    if box:
        sbar.append("".join([wc.color("green"), "SEC", wc.color("default")]))
    else:
        sbar.append("".join([wc.color("red"), "!SEC", wc.color("default")]))

    result = "".join(sbar)
    if result:
        result = f"{wc.color('default')}E2E:{result}"

    if box:
        wc.buffer_set(buf, "localvar_set_e2e_encrypted", "true")
    else:
        wc.buffer_set(buf, "localvar_set_e2e_encrypted", "false")

    return result
