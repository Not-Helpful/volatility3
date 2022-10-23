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
@author:       Gustavo Moreira (Ported by Brandon Lara)
@license:      GNU General Public License 2.0
@contact:      gmoreira@gmail.com (Brandon Lara: blara4@lsu.edu)
@organization:
"""

from volatility3.framework.configuration import requirements

class Linux_Process_ptrace(interfaces.plugins.PluginInterface):
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
                               version = (2, 1, 0))]
    
    PT_FLAGS = (
        ("PTRACED", 0x00001),
        ("DTRACE", 0x00002),
        ("SEIZED", 0x10000),
    )

    def run(self):
        