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

from zLOG import LOG, INFO

from AccessControl.PermissionRole import rolesForPermissionOn

try:
    from Products.CMFCore.CatalogTool import CatalogTool

    LOG('PluggableUserFolder', INFO, 'Patching CMF')

    def mergedLocalRoles(object, withgroups=0):
        """Returns a merging of object and its ancestors'
        __ac_local_roles__.
        When called with withgroups=1, the keys are
        of the form user:foo and group:bar."""
        # Modified from AccessControl.User.getRolesInContext().
        merged = {}
        object = getattr(object, 'aq_inner', object)
        while 1:
            if hasattr(object, '__ac_local_roles__'):
                dict = object.__ac_local_roles__ or {}
                if callable(dict): dict = dict()
                for k, v in dict.items():
                    if withgroups: k = 'user:'+k # groups
                    if merged.has_key(k):
                        merged[k] = merged[k] + v
                    else:
                        merged[k] = v
            # deal with groups
            if withgroups:
                if hasattr(object, '__ac_local_group_roles__'):
                    dict = object.__ac_local_group_roles__ or {}
                    if callable(dict): dict = dict()
                    for k, v in dict.items():
                        k = 'group:'+k
                        if merged.has_key(k):
                            merged[k] = merged[k] + v
                        else:
                            merged[k] = v
            # end groups
            if hasattr(object, 'aq_parent'):
                object = object.aq_parent
                object = getattr(object, 'aq_inner', object)
                continue
            if hasattr(object, 'im_self'):
                object = object.im_self
                object = getattr(object, 'aq_inner', object)
                continue
            break
        return merged


    def allowedRolesAndUsers(self):
        """
        Return a list of roles, users and groups with View permission.
        Used by PortalCatalog to filter out items you're not allowed to see.
        """
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
    #IndexableObjectWrapper.allowedRolesAndUsers = allowedRolesAndUsers


    def _listAllowedRolesAndUsers(self, user):
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

