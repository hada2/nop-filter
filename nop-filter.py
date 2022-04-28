#!/usr/bin/python

import idaapi
import idautils
import idc

NOPFILTER_VERSION = "1.0"

def hide():
    end_ea = None

    for head in idautils.Heads():
        if end_ea and head != end_ea:
            continue

        end_ea = None
        mnem = idc.print_insn_mnem(head)

        if mnem == "nop":
            end_ea = head

            while idc.print_insn_mnem(end_ea) == "nop":
                idc.del_hidden_range(end_ea)
                end_ea = idc.next_head(end_ea)

            idc.add_hidden_range(head, end_ea, "", None, None, 0xFFFFFFFF)
            idc.update_hidden_range(head, False)

def PLUGIN_ENTRY():
    return nop_filter()

class nop_filter(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = ""
    help = ""
    wanted_name = "NOP Filter"
    wanted_hotkey = ""

    def init(self):
        global nop_filter_init

        if "nop_filter_init" not in globals():
            print("NOP Filter v{} (c) Hiroki Hada".format(NOPFILTER_VERSION))

        nop_filter_init = True

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        hide()
        print("NOP filtered")

    def term(self):
        pass

