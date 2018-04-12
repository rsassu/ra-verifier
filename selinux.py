#!/usr/bin/env python
# -*- coding: utf-8 -*-

# selinux.py: query a SELinux policy
#
# Copyright (C) 2014 Politecnico di Torino, Italy
#                    TORSEC group -- http://security.polito.it
#
# Author: Roberto Sassu <roberto.sassu@polito.it>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.

from log import *
from subprocess import *
from util import *
import os

SELINUX_POLICY_VERSION = 29
SELINUX_POLICY_PATH_DEFAULT = '/etc/selinux/targeted/policy/policy.' + str(SELINUX_POLICY_VERSION)
selinux_class_list = ['file']
tcb_subjects = []


class SELinux(object):
    def parse_rule(self, rule = None):
        rule_is_cond = False
        r = rule.split()
        if len(r) == 0:
            return None

        if r[0] == 'ET' or r[0] == 'DT':
            if r[0] == 'DT':
                return None
            del r[0]
            rule_is_cond = True

        if r[0] == 'allow':
            perm_list = []
            for perm in r[3:]:
                if perm == '{':
                    continue
                elif perm == '};':
                    break
                else:
                    perm_list.append(perm)
                    if perm == r[3]:
                        break

            cond_list = []
            if rule_is_cond == True:
                cond_list = rule[rule.index('[') + 1:rule.index(']')].strip()

            parsed_rule = dict(type = r[0], scontext = r[1],
                               tcontext = selinux_context(r[2]),
                               permlist = perm_list, condlist = cond_list)

            parsed_rule['class'] = selinux_class(r[2])
        elif r[0] == 'type_transition':
            new_context = r[5]
            if new_context.endswith(';'):
                new_context = new_context[:-1]

            parsed_rule = dict(type = r[0], scontext = r[1], tcontext = r[2],
                               newcontext = new_context)
            parsed_rule['class'] = r[4]
            if len(r) == 7:
                new_filename = r[6][:-1]
                parsed_rule['newfilename'] = new_filename
        else:
            return None

        return parsed_rule

    def type_list(self, type = None, cls = None):
        suffix = ''
        if cls is not None:
            suffix = ':' + cls
        try:
            return [t + suffix for t in self.types[type]]
        except:
            return [type + suffix]

    def __init__(self, policy_path = None, use_conditionals = True,
                 active_processes = [], policy_source = 'selinux'):
        self.policy_path = SELINUX_POLICY_PATH_DEFAULT
        if policy_path != None:
            self.policy_path = policy_path
        self.attributes = {}
        self.types = {}

        self.reads = {}
        self.writes = {}

        p = ['\n']
        if policy_source == 'selinux':
            p = Popen(['seinfo', '-t', '-x', self.policy_path],
                stdout = PIPE, stderr = PIPE).communicate()[0].splitlines()

        for l in p[1:]:
            alias = 0
            r = l.split(' ')
            if len(r) < 5:
                continue

            type = r[4]
            if type[-1] == ',' or type[-1] == ';':
                type = type[:-1]

            if type not in self.attributes:
                self.attributes[type] = set()

            aliases = []
            for attribute in r[5:]:
                if attribute == 'alias':
                    alias = 1
                    continue
                if alias == 1 and attribute == '{':
                    continue
                if alias == 1 and attribute == '};':
                    alias = 0
                    continue
		if alias == 1:
                    aliases.append(attribute)
                    continue;

                for t in aliases + [type]:
                    self.attributes[t].add(attribute[:-1])
                    if attribute[:-1] not in self.types:
                        self.types[attribute[:-1]] = set()
                    self.types[attribute[:-1]].add(t)

        conditional_opt = ''
        if use_conditionals == True:
            conditional_opt = 'C'

        if policy_source == 'selinux':
            sesearch_args = ['sesearch', '-A',
                             '-p', 'read,write', self.policy_path]
        elif policy_source == 'infoflow':
            sesearch_args = ['cat', self.policy_path]
        else:
            return

        result = Popen(sesearch_args, stdout = PIPE,
                       stderr = PIPE).communicate()[0].splitlines()

        for rule in result:
            parsed_rule = self.parse_rule(rule)
            if parsed_rule is None:
                continue
            if parsed_rule['class'] in ['dir', 'sock_file', 'lnk_file']:
                continue
            for subj in self.type_list(parsed_rule['scontext']):
                if len(active_processes) > 0 and \
                  selinux_type(subj) not in active_processes:
                    continue
                if 'read' in parsed_rule['permlist'] or \
                  'execute' in parsed_rule['permlist'] or \
                  'execute_notrans' in parsed_rule['permlist']:
                    if subj not in self.reads:
                        self.reads[subj] = set()
                    objs_read = self.type_list(parsed_rule['tcontext'],
                                               parsed_rule['class'])
                    self.reads[subj].update(objs_read)
                if 'write' in parsed_rule['permlist']:
                    if subj not in self.writes:
                        self.writes[subj] = set()
                    objs_written = self.type_list(parsed_rule['tcontext'],
                                                  parsed_rule['class'])
                    self.writes[subj].update(objs_written)
