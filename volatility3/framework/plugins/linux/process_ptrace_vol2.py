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
@author:       Gustavo Moreira
@license:      GNU General Public License 2.0
@contact:      gmoreira@gmail.com
@organization:
"""

import volatility.plugins.linux.pslist as linux_pslist
from volatility.renderers import TreeGrid


class linux_process_ptrace(linux_pslist.linux_pslist):
    '''Gathers tracer and tracee processes'''

    PT_FLAGS = (
        ("PTRACED", 0x00001),
        ("DTRACE", 0x00002),
        ("SEIZED", 0x10000),
    )

    def unified_output(self, data):
        return TreeGrid([("Arguments", str),
                       ("Pid", int),
                       ("Uid", int),
                       ("Gid", int)],
                        self.generator(data))

    def _ptrace_flag_to_text(self, ptrace_flags):
        flags = []
        for text, value in self.PT_FLAGS:
            if ptrace_flags & value != 0:
                flags.append(text)

        return "|".join(flags)

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

    def generator(self, tasks):
        for name, pid, ppid, flags, traced_by, tracing in self.get_ptrace_info(tasks):
            yield (0, [str(name),
                       int(pid),
                       str(ppid),
                       str(flags),
                       str(traced_by),
                       str(tracing),
                       ]
            )

    def render_text(self, outfd, tasks):
        self.table_header(outfd, [("Name", "20"),
                                  ("Pid", "15"),
                                  ("PPid", "15"),
                                  ("Flags", "22"),
                                  ("Traced by", "15"),
                                  ("Tracing", "")])

        for name, pid, ppid, flags, traced_by, tracing in self.get_ptrace_info(tasks):
            self.table_row(outfd, name, pid, ppid, flags, traced_by, tracing)