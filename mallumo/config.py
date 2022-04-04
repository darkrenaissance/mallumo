"""Configuration utilities"""
import weechat as wc

from mallumo.globalvars import (CONFIG_SECTIONS, CONFIG_FILE, E2E_STATUSBAR,
                                SCRIPT_NAME)
from mallumo.statusbar import e2e_statusbar_cb
from mallumo.utils import iprnt


def free_all_config():
    """Free config items that were set"""
    for section in CONFIG_SECTIONS.values():
        wc.config_section_free_options(section)
        wc.config_section_free(section)

    wc.config_free(CONFIG_FILE)


def shutdown():
    """Teardown when unloading plugin"""
    wc.config_write(CONFIG_FILE)
    free_all_config()
    wc.bar_item_remove(E2E_STATUSBAR)
    return wc.WEECHAT_RC_OK


def new_section(name):
    """Install a new config section"""
    return wc.config_new_section(CONFIG_FILE, name, 0, 0, "", "", "", "", "",
                                 "", "", "", "", "")


def new_option(section, option):
    """Install a new option in a config section"""
    wc.config_new_option(CONFIG_FILE, CONFIG_SECTIONS[section], option[0],
                         option[1], option[2], "", 0, 0, option[3], option[3],
                         0, "", "", "", "", "", "")


def init_config():
    """Initialize plugin configuration upon loading module"""
    iprnt("", "Initializing configuration")

    global CONFIG_FILE
    CONFIG_FILE = wc.config_new(SCRIPT_NAME, "", "")
    CONFIG_SECTIONS["general"] = new_section("general")

    opts = [
        ("debug", "boolean", "script debugging", "off"),
        ("secret", "string", "secret key (base64)", ""),
    ]

    for opt in opts:
        new_option("general", opt)

    wc.config_read(CONFIG_FILE)

    iprnt("", "Initializing statusbar")
    global E2E_STATUSBAR
    E2E_STATUSBAR = wc.bar_item_new(SCRIPT_NAME, "e2e_statusbar_cb", "")
    wc.bar_item_update(SCRIPT_NAME)
