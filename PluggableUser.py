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

__doc__ = '''Pluggable User'''
__version__ = '$Revision$'[11:-2]

from PluggableUserFolder import LOG, DEBUG, ERROR

import Acquisition
from AccessControl import ClassSecurityInfo
from AccessControl.User import User
from AccessControl.PermissionRole import _what_not_even_god_should_do

from PluginInterfaces import IRolePlugin

class PluggableUserMixin:
    """A mixin for user that overrides the methods for getting roles"""
    security = ClassSecurityInfo()

    def getUserName(self):
        return str(self.name)

    def getRoles(self):
        """Return the list of roles assigned to a user."""
        LOG('PluggableUser', DEBUG, 'getRoles',
            'User: %s\n' % self.getId())
        from Acquisition import aq_base
        plugins = self.acl_users._get_plugins(IRolePlugin)
        # plugins = self._sort_plugins(plugins, self.role_order)
        roles = self.roles[:] # Make sure it's a copy, and not the original
        for plugin in plugins:
            roles = plugin.modifyGlobalRoles(self.getId(), roles)

        if self.name != 'Anonymous User':
            roles = tuple(roles) + ('Authenticated',)
        return tuple(roles)

    def getRolesInContext(self, object):
        """Return the list of roles assigned to the user,
           including local roles assigned in context of
           the passed in object."""

        LOG('PluggableUser', DEBUG, 'getRolesInContext',
            'User: %s\nObject: %s\n' % \
            (self.getId(), str(object)))

        userid = self.getId()
        roles = self.getRoles()
        local = {}
        inner_object = getattr(object, 'aq_inner', object)
        while 1:
            local_roles = getattr(inner_object, '__ac_local_roles__', None)
            dict = local_roles or {}
            if callable(dict):
                dict = dict()
            for r in dict.get(userid, []):
                local[r] = 1
            inner = getattr(inner_object, 'aq_inner', inner_object)
            parent = getattr(inner, 'aq_parent', None)
            if parent is not None:
                inner_object = parent
                continue
            if hasattr(inner_object, 'im_self'):
                inner_object = object.im_self
                object = getattr(inner_object, 'aq_inner', inner_object)
                continue
            break
        roles = list(roles) + local.keys()

        plugins = self.acl_users._get_plugins(IRolePlugin)
        LOG('PluggableUser', DEBUG, 'getRolesInContext',
            'User: %s\nPlugins: %s\n' % \
            (userid, str(plugins)))
        for plugin in plugins:
            roles = plugin.modifyLocalRoles(userid, object, roles)

        return roles

    def allowed(self, object, object_roles=None):
        """Check whether the user has access to object. The user must
           have one of the roles in object_roles to allow access."""
        LOG('PluggableUser', DEBUG, 'allowed',
            'Roles: %s\nUser: %s\nObject: %s\n' % \
            (object_roles, self.getId(), str(object)))

        if object_roles is _what_not_even_god_should_do: return 0

        # Short-circuit the common case of anonymous access.
        if object_roles is None or 'Anonymous' in object_roles:
            return 1

        # Provide short-cut access if object is protected by 'Authenticated'
        # role and user is not nobody
        if 'Authenticated' in object_roles and (
            self.getUserName() != 'Anonymous User'):
            return 1

        # Check for ancient role data up front, convert if found.
        # This should almost never happen, and should probably be
        # deprecated at some point.
        if 'Shared' in object_roles:
            object_roles = self._shared_roles(object)
            if object_roles is None or 'Anonymous' in object_roles:
                return 1

        # Check for a role match with the normal roles given to
        # the user, then with local roles only if necessary. We
        # want to avoid as much overhead as possible.
        user_roles = self.getRoles()
        for role in object_roles:
            if role in user_roles:
                if self._check_context(object):
                    return 1
                return None

        # Still have not found a match, so check local roles. We do
        # this manually rather than call getRolesInContext so that
        # we can incur only the overhead required to find a match.
        inner_obj = getattr(object, 'aq_inner', object)
        userid = self.getId()
        plugins = self.acl_users._get_plugins(IRolePlugin)
        LOG('PluggableUser', DEBUG, 'allowed',
            'Roles: %s\nUser: %s\nPlugins: %s\n' % \
            (object_roles, userid, str(plugins)))
        while 1:
            local_roles = getattr(inner_obj, '__ac_local_roles__', None)
            if local_roles:
                if callable(local_roles):
                    local_roles = local_roles()
                dict = local_roles or {}
                local_roles = dict.get(userid, [])
            else:
                local_roles = []

            for role in object_roles:
                if role in local_roles:
                    isallowed = 1
                else:
                    isallowed = 0
                # Go through all the plugins, to see if they want to modify
                for plugin in plugins:
                    isallowed = plugin.isUserAllowed(userid,
                        inner_obj, role, isallowed)

                if isallowed:
                    # OK, we do have the required permissions!
                    if self._check_context(object):
                        return 1
                    return 0 # But this is acquisition trickery!

            inner = getattr(inner_obj, 'aq_inner', inner_obj)
            parent = getattr(inner, 'aq_parent', None)
            if parent is not None:
                inner_obj = parent
                continue
            if hasattr(inner_obj, 'im_self'):
                inner_obj = inner_obj.im_self
                inner_obj = getattr(inner_obj, 'aq_inner', inner_obj)
                continue
            break
        return None

    def getGroups(self):
        LOG('PluggableUser', DEBUG, 'getGroups()')
        return self.acl_users.getGroupsForUser(self.getId())


class PluggableUser(PluggableUserMixin, User):
    pass


class PluggableUserWrapper(PluggableUserMixin, Acquisition.Implicit):
    pass
