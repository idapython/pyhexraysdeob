
import os

import ida_idaapi
import ida_loader
import ida_kernwin
import ida_hexrays

my_dirname, _ = os.path.split(__file__)

setattr(ida_hexrays, "MMAT_DEOB_MAP", getattr(ida_hexrays, "MMAT_LOCOPT"))

class pyhexraysdeob_t(ida_idaapi.plugin_t):
    flags = 0
    comment = "Show microcode"
    help = ""
    wanted_name = "Python Microcode explorer (pyhexraysdeob)"
    wanted_hotkey = ""

    def __init__(self):
        self.black_list = []
        self.white_list = []
        self.activated = False

    def toggle_activated(self):
        if not self.activated:
            # Install our block and instruction optimization classes.
            import pattern_deobfuscate
            self.oco = pattern_deobfuscate.obf_compiler_optimizer_t()
            self.oco.install()
            import unflattener
            self.cfu = unflattener.cf_unflattener_t(self)
            self.cfu.install()
        else:
            # Uninstall our block and instruction optimization classes.
            self.oco.remove()
            self.oco = None
            self.cfu.remove()
            self.cfu = None
        self.activated = not self.activated
        print("%s is now %sactivated" % (self.wanted_name, "" if self.activated else "de-"))

    def init(self):
        if not ida_hexrays.init_hexrays_plugin():
            print("pyhexraysdeob: no decompiler, skipping")
            return ida_idaapi.PLUGIN_SKIP
        print("Hex-rays version %s has been detected, %s ready to use" % (
            ida_hexrays.get_hexrays_version(),
            self.wanted_name))

        import sys
        modules_path = os.path.join(my_dirname, "pyhexraysdeob_modules")
        if not modules_path in sys.path:
            sys.path.append(modules_path)

        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        if arg == 0:
            self.toggle_activated()
        elif arg == 0xbeef:
            self.flags |= ida_loader.PLUGIN_UNL
        elif arg == 2:
            fix_calls_to_alloca_probe() # unimp
        elif arg == 3:
            show_microcode_explorer() # unimp
        return True

    def term(self):
        if self.activated:
            self.toggle_activated()

def PLUGIN_ENTRY():
    return pyhexraysdeob_t()


