from volatility3.framework import interfaces
from typing import Callable, Iterable, List, Type
from volatility3.framework import renderers, interfaces, layers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins import timeliner
from volatility3.plugins.windows import info, pslist


class Threads(interfaces.plugins.PluginInterface):
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
                requirements.PluginRequirement(name = 'pslist',
                                               plugin = pslist.PsList,
                                               version = (2, 0, 0))]
                                               
    @classmethod
    def list_threads(cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        procs#,
        #filter_func: Callable[
        #    [interfaces.objects.ObjectInterface], bool
        #] = lambda _: False,
    ) -> Iterable[interfaces.objects.ObjectInterface]:
    
        kvo = context.layers[layer_name].config["kernel_virtual_offset"]
        ntkrnlmp = context.module(symbol_table, layer_name=layer_name, offset=kvo)
        tleoffset = ntkrnlmp.get_type("_ETHREAD").relative_child_offset(
            "ThreadListEntry"
        )
        
        for proc in procs:
            ethreads = []
            first_ethread = ntkrnlmp.object(
                    object_type="_ETHREAD",
                    offset=proc.ThreadListHead.Flink - tleoffset,
                    absolute=True,
                )
            ethreads.append(first_ethread)
            for ethread in first_ethread.ThreadListEntry:
                ethreads.append(ethread)
            yield (proc, ethreads)
                
        
    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        kernel = self.context.modules[self.config['kernel']]

        return renderers.TreeGrid([("PID", str),
                                   ("Base", format_hints.Hex)],
                                  self._generator(pslist.PsList.list_processes(self.context,
                                                                               kernel.layer_name,
                                                                               kernel.symbol_table_name,
                                                                               filter_func = filter_func)))
    def _generator(self, procs):
        kernel = self.context.modules[self.config["kernel"]]
        for proc,ethreads in self.list_threads(self.context,
            kernel.layer_name,
            kernel.symbol_table_name,
            procs):
            yield (0, (str(proc.UniqueProcessId), format_hints.Hex(ethreads[0].vol.offset)))
            del ethreads[0]
            for ethread in ethreads:
                yield (0, ("....", format_hints.Hex(ethread.vol.offset)))
        
            
        
        