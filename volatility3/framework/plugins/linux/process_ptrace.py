# Volatility
# Copyright (C) 2007-2022 Volatility Foundation
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""
@author:       Gustavo Moreira (Ported to Volatility 3 by Brandon Lara)
@license:      GNU General Public License 2.0
@contact:      gmoreira@gmail.com (Brandon Lara: blara4@lsu.edu)
@organization:
"""

from py import process
from volatility3.framework.configuration import requirements
from volatility3.framework import renderers, interfaces
from volatility3.plugins.linux import pslist
from volatility3.framework.renderers import format_hints

class Process_ptrace(interfaces.plugins.PluginInterface):
    """Gathers tracer and tracee processes"""

    _required_framework_version = (2, 0, 0)

    _version = (2, 1, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name = 'kernel', description = 'Linux kernel',
                                           architectures = ["Intel32", "Intel64"]),
            requirements.ListRequirement(name = 'pid',
                                         description = 'Filter on specific process IDs',
                                         element_type = int,
                                         optional = True),
            requirements.PluginRequirement(name = 'pslist',
                               plugin = pslist.PsList,
                               version = (2, 1, 0)),
            requirements.BooleanRequirement(name="threads",
                                            description="Include user threads",
                                            optional=True,
                                            default=False)]
    
    PT_FLAGS = (
        ("PTRACED", 0x00001),
        ("DTRACE", 0x00002),
        ("SEIZED", 0x10000),
    )

    def run(self):
        
        filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))
        
        return renderers.TreeGrid([("Arguments", str),
                       ("Pid", int),
                       ("Uid", int),
                       ("Gid", int)],
                        self._generator(
                                      pslist.PsList.list_tasks(self.context,
                                                               self.config['kernel'],
                                                               filter_func = filter_func)))

    def get_ptrace_info(self, tasks):
        for task in tasks:
            tracing_list = []
            for task_being_traced in task.ptraced.list_of_type("task_struct", "ptrace_entry"):
                tracing_list.append(str(task_being_traced.pid))

            if task.ptrace == 0 and not tracing_list:
                continue

            flags = self._ptrace_flag_to_text(task.ptrace)

            traced_by = task.parent.tgid if task.real_parent.tgid != task.parent.tgid else ""

            tracing = ",".join(tracing_list)

            yield task.comm, task.tgid, task.real_parent.tgid, flags, traced_by, tracing

    def _generator(self, procs):
        for name, pid, ppid, flags, traced_by, tracing in self.get_ptrace_info(procs):
            yield (0, [str(name),
                       int(pid),
                       str(ppid),
                       str(flags),
                       str(traced_by),
                       str(tracing),
                       ]
            )
