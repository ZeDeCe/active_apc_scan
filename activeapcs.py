from volatility3.framework import interfaces
from typing import Callable, Iterable, List, Type
from volatility3.framework import renderers, interfaces, layers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins import timeliner
from volatility3.plugins.windows import info, threads, pslist
from pprint import pprint


class ActiveApcs(interfaces.plugins.PluginInterface):
    _version = (1, 0, 0)
    _required_framework_version = (2, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.ModuleRequirement(name = 'kernel', description = 'Windows kernel',
                                               architectures = ["Intel32", "Intel64"]),
                requirements.ListRequirement(name = 'pid',
                                             element_type = int,
                                             description = "Process IDs to include (all other processes are excluded)",
                                             optional = True),
                requirements.PluginRequirement(name = 'threads',
                                               plugin = threads.Threads,
                                               version = (1, 0, 0))]
                                               
    @classmethod
    def list_apc_threads(cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        threadprocpair#,
        #filter_func: Callable[
        #    [interfaces.objects.ObjectInterface], bool
        #] = lambda _: False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
    
        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)
        lioffset = ntkrnlmp.get_type("_KAPC").relative_child_offset(
            "ApcListEntry"
        )
        
        for proc,threads in threadprocpair:
            for thread in threads:
                apclist = []
                try:
                    apclisthead = thread.Tcb.ApcState.ApcListHead[1]
                    apchead = apclisthead.Flink
                    while apclisthead.vol.offset != apchead:
                        myapc = ntkrnlmp.object(
                            object_type="_KAPC",
                            offset=apchead - lioffset,
                            absolute=True,
                        )
                        
                        if myapc.ApcMode == 1:
                            apclist.append(myapc)
                        apchead = apchead.Flink
                    yield (proc, thread, apclist)
                except exceptions.InvalidAddressException:
                    pass

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        kernel = self.context.modules[self.config['kernel']]

        return renderers.TreeGrid([("PID", str),
                                   ("Thread Base", format_hints.Hex),
                                   ("APC Base", format_hints.Hex)],
                                  self._generator(threads.Threads.list_threads(self.context,
                                                                               kernel.layer_name,
                                                                               kernel.symbol_table_name,
                                                                               pslist.PsList.list_processes(self.context,
                                                                               kernel.layer_name,
                                                                               kernel.symbol_table_name,
                                                                               filter_func = filter_func))))
    def _generator(self, threadprocpair):
        kernel = self.context.modules[self.config["kernel"]]
        for proc,thread,apclist in self.list_apc_threads(self.context,
            kernel.layer_name,
            kernel.symbol_table_name,
            threadprocpair):
            for apc in apclist:
                yield (0, (str(proc.UniqueProcessId), format_hints.Hex(thread.vol.offset), format_hints.Hex(apc.vol.offset)))