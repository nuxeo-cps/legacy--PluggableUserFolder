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

from PluggableUserFolder import LOG, INFO, DEBUG, PluggableUserFolder
from AccessControl.PermissionRole import rolesForPermissionOn

# These CMF patches is also done by CPS3, so if it is already done, skip it.

_cmf_localroles_patch = 0
try:
    import CPSCore.utils
    _cmf_localroles_patch = 1
except ImportError:
    pass

if not _cmf_localroles_patch:
    # Used outside CPS.
    try:
        from Products.CMFCore import utils
        from Products.CMFCore.CatalogTool import IndexableObjectWrapper,\
            CatalogTool

        LOG('PluggableUserFolder', INFO, 'Patching CMF')

        def mergedLocalRoles(object, withgroups=0):
            aclu = object.acl_users
            if hasattr(aclu, 'mergedLocalRoles'):
                return aclu.mergedLocalRoles(object, withgroups)
            return utils._mergedLocalRoles(object)

        #Patch this into CPSCore.utils
        utils.mergedLocalRoles = mergedLocalRoles

        def _allowedRolesAndUsers(ob):
            aclu = object.acl_users
            if hasattr(aclu, '_allowedRolesAndUsers'):
                return aclu._allowedRolesAndUsers(ob)
            # The userfolder does not have CPS group support
            allowed = {}
            for r in rolesForPermissionOn('View', ob):
                allowed[r] = 1
            localroles = utils.mergedLocalRoles(ob) # groups
            for user_or_group, roles in localroles.items():
                for role in roles:
                    if allowed.has_key(role):
                        allowed[user_or_group] = 1
            if allowed.has_key('Owner'):
                del allowed['Owner']
            return list(allowed.keys())

        def allowedRolesAndUsers(self):
            """
            Return a list of roles, users and groups with View permission.
            Used by PortalCatalog to filter out items you're not allowed to see.
            """
            ob = self._IndexableObjectWrapper__ob # Eeek, manual name mangling
            return _allowedRolesAndUsers(ob)
        IndexableObjectWrapper.allowedRolesAndUsers = allowedRolesAndUsers

        def _getAllowedRolesAndUsers(self, user):
            aclu = object.acl_users
            if hasattr(aclu, '_getAllowedRolesAndUsers'):
                return aclu._getAllowedRolesAndUsers(ob)
            # The userfolder does not have CPS group support
            result = list(user.getRoles())
            result.append('Anonymous')
            result.append('user:%s' % user.getUserName())
            return result

        def _listAllowedRolesAndUsers(self, user):
            aclu = self.acl_users
            if hasattr(aclu, '_getAllowedRolesAndUsers'):
                return aclu._getAllowedRolesAndUsers(user)
            return CatalogTool.old_listAllowedRolesAndUsers(self, user)

        if not hasattr(CatalogTool, 'old_listAllowedRolesAndUsers'):
            CatalogTool.old_getAllowedRolesAndUsers = CatalogTool._listAllowedRolesAndUsers

        CatalogTool._listAllowedRolesAndUsers = _listAllowedRolesAndUsers

    except ImportError:
        # Not a CMF Installation. No patching needed.
        pass

