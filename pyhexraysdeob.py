
import os

import ida_idaapi
import ida_loader
import ida_kernwin
import ida_hexrays
import sys
from pyhexraysdeob_modules.unflattener import *

setattr(ida_hexrays, "MMAT_DEOB_MAP", getattr(ida_hexrays, "MMAT_LOCOPT"))

class pyhexraysdeob_t(ida_idaapi.plugin_t):

    def __init__(self):
        self.black_list = []
        self.white_list = []
        self.wanted_name = "Emotet unflattener"
        self.activated = False
        self.flags = 0
        self.RUN_MLTPL_DISPATCHERS = True

    def toggle_activated(self):
        if not self.activated:
            self.cfu = cf_unflattener_t(self)
            self.cfu.install()
        else:
            self.cfu.remove()
            self.cfu = None
        self.activated = not self.activated
        print(f"{self.wanted_name}, activated={self.activated}")

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            print("pyhexraysdeob: no decompiler, skipping")
            return ida_idaapi.PLUGIN_SKIP
        print(f"Hex-rays version {ida_hexrays.get_hexrays_version()} has been detected, {self.wanted_name} ready to use")

        # really needed ?
        # modules_path = os.path.join(my_dirname, "pyhexraysdeob_modules")
        # if not modules_path in sys.path:
        #    sys.path.append(modules_path)

        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        if arg == 0:
            self.toggle_activated()
        elif arg == 0xbeef:
            self.flags |= ida_loader.PLUGIN_UNL
        return True

    def enforce_unflatten(self, vaddr):
        """
        Enforce the unflattening of a function at addr.
        :param vaddr: Virtual address of function
        """
        if self.activated:
            if vaddr in self.black_list:
                self.black_list.remove(vaddr)
            if vaddr not in self.white_list:
                self.white_list.append(vaddr)

    def term(self):
        if self.activated:
            self.toggle_activated()


def PLUGIN_ENTRY():
    return pyhexraysdeob_t()


