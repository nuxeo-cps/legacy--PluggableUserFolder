# Copyright (c) 2003 Nuxeo SARL <http://nuxeo.com>
# Copyright (c) 2003 CEA <http://www.cea.fr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# $Id$

"""
  CatalogToolWithGroups
  Patches CMF Catalog Tool to add groups support in allowedRolesAndUsers.
"""

__version__ = '$Revision$'[11:-2]

from zLOG import LOG, INFO, DEBUG

from AccessControl.PermissionRole import rolesForPermissionOn

try:
    from Products.CMFCore import utils
    from Products.CMFCore.CatalogTool import IndexableObjectWrapper,\
         CatalogTool

    LOG('PluggableUserFolder', INFO, 'Patching CMF')

    def mergedLocalRoles(object, withgroups=0):
        """Returns a merging of object and its ancestors'
        __ac_local_roles__.
        When called with withgroups=1, the keys are
        of the form user:foo and group:bar."""

        merged = object.acl_users.mergedLocalRoles(object)
        if withgroups:
            result = {}
            for user, roles in merged.items():
                result['user:'+user] = roles
            merged = result
        return merged

    utils._mergedLocalRoles = mergedLocalRoles
    utils.mergedLocalRoles = mergedLocalRoles


    def allowedRolesAndUsers(self):
        """
        Return a list of roles, users and groups with View permission.
        Used by PortalCatalog to filter out items you're not allowed to see.
        """
        LOG('PluggableUserFolder', 0, 'Patched allowedRolesAndUsers()')
        ob = self._IndexableObjectWrapper__ob # Eeek, manual name mangling
        allowed = {}
        for r in rolesForPermissionOn('View', ob):
            allowed[r] = 1
        localroles = mergedLocalRoles(ob, withgroups=1) # groups
        for user_or_group, roles in localroles.items():
            for role in roles:
                if allowed.has_key(role):
                    allowed[user_or_group] = 1
        if allowed.has_key('Owner'):
            del allowed['Owner']
        return list(allowed.keys())
    IndexableObjectWrapper.allowedRolesAndUsers = allowedRolesAndUsers


    def _listAllowedRolesAndUsers(self, user):
        LOG('PluggableUserFolder', DEBUG, 'Patched _listAllowedRolesAndUsers()')
        result = list(user.getRoles())
        result.append('Anonymous')
        result.append('user:%s' % user.getUserName())
        # deal with groups
        getGroups = getattr(user, 'getGroups', None)
        if getGroups is not None:
            for group in getGroups():
                result.append('group:%s' % group)
        # end groups
        return result
    CatalogTool._listAllowedRolesAndUsers = _listAllowedRolesAndUsers

except ImportError:
    pass

