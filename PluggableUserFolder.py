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

__doc__ = '''Pluggable User Folder'''
__version__ = '$Revision$'[11:-2]

# Note that these imports are imported here to be available,
# so don't remove them even though they are unused.
from zLOG import LOG, DEBUG, BLATHER, INFO, PROBLEM, WARNING, ERROR
import os
from urllib import quote, urlencode

if os.environ.get("ZOPE_PLUGGABLE_LOGGING", None) == "OFF":
    def LOG(*args, **kw):
        pass

from Globals import DTMLFile, MessageDialog
from Acquisition import aq_base
from AccessControl import ClassSecurityInfo, Permissions
from AccessControl.User import BasicUserFolder, _noroles
from AccessControl.Role import RoleManager, DEFAULTMAXLISTUSERS
from AccessControl.PermissionRole import rolesForPermissionOn
from ZPublisher import BeforeTraverse
from ZPublisher.HTTPRequest import HTTPRequest

from OFS.ObjectManager import ObjectManager
from OFS.SimpleItem import Item

from PluginInterfaces import IAuthenticationPlugin, IIdentificationPlugin, \
    IRolePlugin, IGroupPlugin
from InternalAuthentication import InternalAuthenticationPlugin
from BasicIdentification import BasicIdentificationPlugin


class ProtectedAuthInfo:
    """An object where the username is not accessible from user code

    This object prevents the user name to be accessed or changed from
    anything by protected code. This means that we can always be sure
    that the username returned from _getUsername() has not been
    compromised by user code. This means we can store this object in a
    session, to have a session authentication.
    """

    def _setAuthInfo(self, authinfo):
        self.__authinfo = authinfo

    def _getAuthInfo(self):
        return self.__authinfo


# Special marker for identification methods and
# user storages that check the password as a part of
# identification and user retrieval
_no_password_check = []
_marker = []

class PluggableUserFolder(ObjectManager, BasicUserFolder):
    """A user folder with plugins

    With this user folder you can plug in different types of identification
    and authentication, and use several of them at once.
    """
    security = ClassSecurityInfo()

    meta_type = 'Pluggable User Folder'
    id = 'acl_users'
    title = 'Pluggable User Folder'

    isPrincipiaFolderish = 1
    isAUserFolder = 1
    maxlistusers = DEFAULTMAXLISTUSERS
    identification_order = 'basic_identification'
    authentication_order = 'internal_authentication'
    group_role_order = ''
    login_page = ''
    logout_page = ''
    encrypt_passwords = 0

    manage_options = (
        ({'label':'Contents', 'action':'manage_main',
          'help':('OFSP','Folder_View.stx')},
         {'label':'Properties', 'action':'manage_userFolderProperties',
          'help':('OFSP','User-Folder_Properties.stx')},)
        + RoleManager.manage_options
        + Item.manage_options
        )

    _product_interfaces = (IAuthenticationPlugin, IIdentificationPlugin,
                           IRolePlugin, IGroupPlugin)

    try:
        from Products.CPSDirectory.IUserFolder import IUserFolder
        __implements__ = (IUserFolder,)
    except ImportError:
        pass

    def __init__(self):
        # As default, add the "Internal" plugins.
        ob = InternalAuthenticationPlugin()
        self._setObject(ob.id, ob)
        ob = BasicIdentificationPlugin()
        self._setObject(ob.id, ob)

    def all_meta_types(self, interfaces=None):
        if interfaces is None:
            if hasattr(self, '_product_interfaces'):
                interfaces = self._product_interfaces
            elif hasattr(self, 'aq_acquire'):
                try:
                    interfaces = self.aq_acquire('_product_interfaces')
                except:
                    pass    # Bleah generic pass is bad

        return ObjectManager.all_meta_types(self, interfaces)

    def _subobject_permissions(self):
        return ()

    def _get_plugins(self, interface=None, include_readonly=1):
        if not include_readonly:
            LOG('PluggableUserFolder', DEBUG, '_get_plugins',
                'Interface: %s\nRO: %s\n' % (str(interface), include_readonly))
        result = []
        for plugin in self.objectValues():
            if interface:
                implements = getattr(plugin, '__implements__', ())
                if not interface in implements:
                    continue
            if not include_readonly and hasattr(plugin, 'isReadOnly') and \
                plugin.isReadOnly():
                continue
            if not include_readonly:
                LOG('PluggableUserFolder', DEBUG, 'found plugin',
                    str(plugin) + '\n')
            result.append(plugin)

        return result

    def _sort_plugins(self, plugin_list, order_string):
        order = [p.strip() for p in order_string.split(',') if p.strip()]
        sorted_list = []
        for plugin_name in order:
            for plugin in plugin_list:
                if plugin.id == plugin_name:
                    sorted_list.append(plugin)
                    plugin_list.remove(plugin)
                    break
        # Add all the remaining unsorted plugins onto the end:
        sorted_list.extend(plugin_list)
        return sorted_list

    def _get_first_plugin(self, interface, include_readonly=0):
        if interface == IAuthenticationPlugin:
            order = self.authentication_order
        elif interface == IIdentificationPlugin:
            order = self.identification_order
        elif interface == IRolePlugin:
            order = self.group_role_order
        elif interface == IGroupPlugin:
            order = self.group_role_order
        else:
            raise "Incorrect interface specified" #XXX make into object

        plugin = None
        for id in order.split(','):
            if hasattr(self, id):
                plugin = getattr(self, id)
                if not include_readonly and hasattr(plugin, 'isReadOnly') \
                   and plugin.isReadOnly():
                    continue
                break
        if plugin is None:
            plugins = self._get_plugins(interface, include_readonly)
            if not plugins:
                # TODO: make into a more specific object
                raise Exception("There are no %s plugins" % str(interface))
            plugin = plugins[0]
        return plugin

    # ----------------------------------
    # ZMI interfaces
    # ----------------------------------

    security.declareProtected(Permissions.manage_users,
        'manage_userFolderProperties')
    manage_userFolderProperties = DTMLFile('zmi/userFolderProps', globals())

    def _munge_order(self, order, interface):
        """Internal support method for ZMI interface"""
        message = ''
        error = 0
        existing_plugs = [p.id for p in self._get_plugins(interface)]
        plugs = order.split(',')
        plugs = [p.strip() for p in plugs if p.strip()]
        for plug in plugs:
            if plug in existing_plugs:
                existing_plugs.remove(plug)
            else:
                message += 'Error: Plugin %s not found\n' % plug
                error = 1
        if not error:
            for plug in existing_plugs:
                message += 'Plugin %s not included in list, appending.\n' % plug
                plugs.append(plug)
        return plugs, message, error

    def manage_setUserFolderProperties(self, maxlistusers=DEFAULTMAXLISTUSERS,
                                       identification_order='',
                                       authentication_order='',
                                       group_role_order='',
                                       login_page=None,
                                       logout_page=None,
                                       REQUEST=None):
        """
        Sets the properties of the user folder.
        """
        message = ''
        error = 0
        iplugs, msg, err = self._munge_order(identification_order,
                                             IIdentificationPlugin)
        message = message + msg
        if err:
            error = 1

        aplugs, msg, err = self._munge_order(authentication_order,
                                             IAuthenticationPlugin)
        message = message + msg
        if err:
            error = 1

        gplugs, msg, err = self._munge_order(group_role_order, IGroupPlugin)
        message = message + msg
        if err:
            error = 1

        try:
            maxlistusers = int(maxlistusers)
        except ValueError:
            error = 1
            message = message + 'Max user list number is not a number'

        if error:
            message = message + 'Changes NOT saved.\n'
        else:
            self.identification_order = ', '.join(iplugs)
            self.authentication_order = ', '.join(aplugs)
            self.group_role_order = ', '.join(gplugs)
            self.maxlistusers = maxlistusers
            message = message + 'Saved Changes.\n'

        if self.login_page is not None:
            self.login_page = login_page

        if self.logout_page is not None:
            self.logout_page = logout_page

        if REQUEST is not None:
            return self.manage_userFolderProperties(
                REQUEST, manage_tabs_message=message)

    # ----------------------------------
    # Public UserFolder object interface
    # ----------------------------------

    security.declareProtected(Permissions.manage_users, 'getUserNames')
    def getUserNames(self):
        """Return a list of usernames"""
        result = []
        plugs = self._get_plugins(IAuthenticationPlugin)
        for plugin in self._sort_plugins(plugs, self.authentication_order):
            for username in plugin.getUserNames():
                if username not in result:
                    result.append(username)
        return result

    security.declareProtected(Permissions.manage_users, 'getUsers')
    def getUsers(self):
        """Return a list of user objects"""
        usernames = []
        result = []
        plugs = self._get_plugins(IAuthenticationPlugin)
        for plugin in self._sort_plugins(plugs, self.authentication_order):
            for user in plugin.getUsers():
                if user.getId() not in usernames:
                    usernames.append(user.getId())
                    result.append(user)
        return result

    security.declareProtected(Permissions.manage_users, 'getUser')
    def getUser(self, name, password=None):
        """Return the named user object or None"""
        plugs = self._get_plugins(IAuthenticationPlugin)
        for plugin in self._sort_plugins(plugs, self.authentication_order):
            user = plugin.getUser(name, password)
            if user:
                return user.__of__(self)
        LOG('PluggableUserFolder', DEBUG, 'getUser',
            'Could not find user %s\n' % name)
        return None

    # Group Support
    security.declareProtected(Permissions.manage_users, 'setUsersOfGroup')
    def setUsersOfGroup(self, users, group):
        LOG('PluggableUserFolder', DEBUG, 'setUsersOfGroup',
            'Group: %s\nUsers: %s\n' % (group, str(users)))
        group = self.getGroupById(group)
        group.setUsers(users)

    security.declareProtected(Permissions.manage_users, 'userFolderAddGroup')
    def userFolderAddGroup(self, groupname, title='', **kw):
        """Creates a group"""
        LOG('PluggableUserFolder', DEBUG, 'userFolderAddGroup')
        plugin = self._get_first_plugin(IGroupPlugin)
        plugin.addGroup(groupname, title)

    security.declareProtected(Permissions.manage_users, 'userFolderDelGroups')
    def userFolderDelGroups(self, groupnames):
        """Deletes groups"""
        plugins = self._get_plugins(IGroupPlugin)
        for group in groupnames:
            for plugin in plugins:
                if plugin.hasGroup(group):
                    plugin.delGroup(group)
                    break # No need to search the other groups

    security.declareProtected(Permissions.manage_users, 'getGroupNames')
    def getGroupNames(self):
        LOG('PluggableUserFolder', DEBUG, 'getGroupNames called')
        groups = []
        for plugin in self._get_plugins(IGroupPlugin):
            groups.extend(plugin.getGroupIds())
        return groups

    security.declareProtected(Permissions.manage_users, 'getGroupById')
    def getGroupById(self, groupname, default=_marker):
        """Returns the given group"""
        LOG('PluggableUserFolder', DEBUG, 'getGroupById: ' + groupname)
        if groupname.startswith('role:'):
            from GroupRoles import Group
            return Group(groupname, title=groupname)

        for plugin in self._get_plugins(IGroupPlugin):
            group = plugin.getGroup(groupname)
            if group is not None:
                return group
        # Group not found
        if default is _marker:
            raise Exception('Group %s not found' % groupname)
        return default

    security.declareProtected(Permissions.manage_users, 'getGroupsForUser')
    def getGroupsForUser(self, userid):
        ismemberof = []
        for plugin in self._get_plugins(IGroupPlugin):
            ismemberof.extend(plugin.getGroupsForUser(userid))
        LOG('PluggableUserFolder', DEBUG, 'getGroupsForUser',
            str(ismemberof)+'\n')
        return tuple(ismemberof)

    security.declareProtected(Permissions.manage_users, 'setGroupsOfUser')
    def setGroupsOfUser(self, groupnames, username):
        """Set the groups of a user"""
        user = self.getUser(username)
        usergroups = self.getGroupsForUser(username)
        # Add to new groups
        for group in groupnames:
            if group not in usergroups:
                groupob = self.getGroupById(group)
                groupob.addUsers((username,))
        # Remove from old groups
        for group in usergroups:
            if group not in groupnames:
                groupob = self.getGroupById(group)
                groupob.removeUsers((username,))

    # Roles plugin support
    def setRolesOfUser(self, roles, username):
        """Sets the users of a role"""
        user = self.getUser(username)
        user.roles = roles

    def setUsersOfRole(self, usernames, role):
        """Sets the users of a role

        Will set the roles on the user object directly. Any role plugins
        that modify the global roles will be ignored.
        """
        for user in self.getUsers():
            userroles = user.roles
            if user.getUserName() in usernames:
                if not role in userroles:
                    userroles.append(role)
                    user.roles = userroles
            else:
                if role in userroles:
                    userroles.remove(role)
                    user.roles = userroles

    def getUsersOfRole(self, role):
        """Gets the users of a role"""
        # XXX This ignores global role mokdifications, but currently
        # There is no plugins that do that, so it's nnot a problem, yet.
        users = []
        plugs = self._get_plugins(IAuthenticationPlugin)
        for plugin in self._sort_plugins(plugs, self.authentication_order):
            users.extend(plugin.getUsersOfRole(role))
        return users

    def userFolderAddRole(self, role):
        """Creates a role"""
        portal = self.aq_inner.aq_parent
        portal._addRole(role)

    def userFolderDelRoles(self, rolenames):
        """Delete roles"""
        portal = self.aq_inner.aq_parent
        portal._delRoles(rolenames, None)

    def getRoleManagementOptions(self, types=['form']):
        options = []
        for plugin in self._get_plugins(IRolePlugin):
            for option in plugin.local_manage_methods:
                if not option['type'] in types:
                    continue
                o = option.copy()
                o['plugin_action'] = 'manage_' + plugin.plugin_id + option['id']
                options.append(o)
        LOG('PluggableUserFolder', DEBUG, 'Role Management Options',
            str(options) + '\n')
        return options

    def mergedLocalRoles(self, object, withgroups=0):
        """Returns all local roles valid for an object"""

        LOG('PluggableUserFolder', DEBUG, 'mergedLocalRoles()')

        merged = {}
        innerobject = getattr(object, 'aq_inner', object)
        while 1:
            if hasattr(innerobject, '__ac_local_roles__'):
                dict = innerobject.__ac_local_roles__ or {}
                if callable(dict): dict = dict()
                for user, roles in dict.items():
                    if not merged.has_key(user):
                        merged[user] = {}
                    for role in roles:
                        merged[user][role] = 1

            inner = getattr(innerobject, 'aq_inner', innerobject)
            parent = getattr(inner, 'aq_parent', None)
            if parent is not None:
                innerobject = parent
                continue
            if hasattr(innerobject, 'im_self'):
                innerobject = innerobject.im_self
                innerobject = getattr(innerobject, 'aq_inner', innerobject)
                continue
            break

        for user, roles in merged.items():
            merged[user] = roles.keys()

        # deal with role management plugins, to get a better list
        plugins = self._get_plugins(IRolePlugin)

        result = {}
        if not withgroups:
            # This is probably not CPS. We will simply return a correct and
            # complete list of all users and their roles in this place.
            for plugin in plugins:
                for user in plugin.getUsersWithRoles(object):
                    if not merged.has_key(user):
                        merged[user] = []

            for plugin in plugins:
                for user in merged.keys():
                    merged[user] = plugin.modifyLocalRoles(user,
                                        object, merged[user])
        else:
            # CPS does not expect you to expand users roles, instead
            # It wants a list of users, and groups and their roles.
            # First, go through the found users, to let the plugins
            # Remove any roles. This may also add roles to the users if they
            # are members of groups, but that is no problem, just overhead.
            # Also this adds the 'user:' prefix to users that CPS
            # wants when withgroups is given.
            for plugin in plugins:
                for user in merged.keys():
                    result['user:' + user] = plugin.modifyLocalRoles(
                        user, object, merged[user])
            # Get the groups
            plugins = self._get_plugins(IGroupPlugin)
            for plugin in plugins:
                for group in plugin.getLocalGroups(object):
                    group_roles = plugin.getGroupRolesOnObject(group, object)
                    for role in plugin.getAcquiredGroupRoles(group, object):
                        for acquired_role in role['roles']:
                            if acquired_role in group_roles:
                                continue
                            group_roles.append(acquired_role)
                    result['group:' + group] = group_roles
        return result

    def mergedLocalRolesWithPath(self, object, withgroups=0):
        """Returns all local roles valid for an object with path"""

        LOG('PluggableUserFolder', DEBUG, 'mergedLocalRolesWithPath()')

        merged = {}
        innerobject = getattr(object, 'aq_inner', object)
        from Products.CMFCore.utils import getToolByName
        utool = getToolByName(innerobject, 'portal_url')

        while 1:
            if hasattr(innerobject, '__ac_local_roles__'):
                dict = innerobject.__ac_local_roles__ or {}
                if callable(dict):
                    dict = dict()
                obj_url = utool.getRelativeUrl(innerobject)
                for user, roles in dict.items():
                    if withgroups:
                        user = 'user:' + user # groups
                    if merged.has_key(user):
                        merged[user].append({'url': obj_url,'roles': roles})
                    else:
                        merged[user] = [{'url': obj_url,'roles': roles}]
            # Deal with groups.
            if withgroups:
                if hasattr(innerobject, '__ac_local_group_roles__'):
                    dict = innerobject.__ac_local_group_roles__ or {}
                    if callable(dict):
                        dict = dict()
                    obj_url = utool.getRelativeUrl(object)
                    for group, roles in dict.items():
                        group = 'group:' + group
                        if merged.has_key(group):
                            merged[group].append(
                                {'url': obj_url, 'roles': roles})
                        else:
                            merged[group] = [{'url': obj_url, 'roles': roles}]
            # end groups
            inner = getattr(innerobject, 'aq_inner', innerobject)
            parent = getattr(inner, 'aq_parent', None)
            if parent is not None:
                innerobject = parent
                continue
            if hasattr(innerobject, 'im_self'):
                innerobject = innerobject.im_self
                innerobject = getattr(innerobject, 'aq_inner', innerobject)
                continue
            break

        # deal with role management plugins, to get a better list
        plugins = self._get_plugins(IRolePlugin)

        if not withgroups:
            # Not in a CPS
            LOG("Pluggable User Folder : mergedLocalRolesWithPath",
                DEBUG, "Not implemented")
        else:
            # CPS does not expect you to expand users roles, instead.
            # It wants a list of users, and groups and their roles.
            # First, go through the found users, to let the plugins.
            # Remove any roles. This may also add roles to the users if they
            # are members of groups, but that is no problem, just overhead.
            # Also this adds the 'user:' prefix to users that CPS wants when
            # withgroups is given.
            result = {}
            for plugin in plugins:
                for user in merged.keys():
                    result[user] = []
                    user_append = result[user].append
                    for dict in merged[user]:
                        user_append(
                            {'url': dict['url'],
                             'roles': plugin.modifyLocalRoles(
                                        user, object, dict['roles'])})
            # Get the groups
            plugins = self._get_plugins(IGroupPlugin)
            for plugin in plugins:
                for group in plugin.getLocalGroups(object):
                    group_name = 'group:' + group
                    result[group_name] = []
                    append_groups = result[group_name].append
                    for dict in merged[group_name]:
                        group_dict = {'url': dict['url'],
                             'roles': plugin.getGroupRolesOnObject(group, object)}
                        if group_dict in result[group_name]:
                            continue
                        append_groups(group_dict)

                    for role in plugin.getAcquiredGroupRoles(group, object):
                        obj_url = utool.getRelativeUrl(role['obj'])
                        for acquired_role in role['roles']:
                            if acquired_role in result[group_name]:
                                continue
                            append_groups(
                                {'roles': [acquired_role], 'url': obj_url})
        return result

    def _allowedRolesAndUsers(self, ob):
        """
        Return a list of roles, users and groups with View permission.
        Used by PortalCatalog to filter out items you're not allowed to see.
        """
        LOG('PluggableUserFolder', DEBUG, '_allowedRolesAndUsers()')
        allowed = {}
        for r in rolesForPermissionOn('View', ob):
            allowed[r] = 1
        localroles = self.mergedLocalRoles(ob, withgroups=1) # groups
        for user_or_group, roles in localroles.items():
            if not ':' in user_or_group:
                user_or_group = 'user:' + user_or_group
            for role in roles:
                if allowed.has_key(role):
                    allowed[user_or_group] = 1
        if allowed.has_key('Owner'):
            del allowed['Owner']
        return list(allowed.keys())

    allowedRolesAndUsers = _allowedRolesAndUsers

    # Search API

    def listUserProperties(self):
        """Lists properties settable or searchable on the users."""
        # MemberTool patch assumes that all user are equal. Therefore
        # only properties all plugins support should be returned.
        plugins = self._get_plugins(IAuthenticationPlugin)
        props = plugins[0].listUserProperties()
        for plugin in plugins[1:]:
            props = [prop for prop in plugin.listUserProperties()
                          if prop in props]
        return tuple(props)

    def searchUsers(self, query={}, props=None, options=None, **kw):
        """Search for users having certain properties.

        If props is None, returns a list of ids:
        ['user1', 'user2']

        If props is not None, it must be sequence of property ids. The
        method will return a list of tuples containing the user id and a
        dictionary of available properties:
        [('user1', {'email': 'foo', 'age': 75}), ('user2', {'age': 5})]

        Options is used to specify the search type if possible. XXX

        Special properties are 'id', 'roles', 'groups'.
        """
        result = []
        for plugin in self._get_plugins(IAuthenticationPlugin):
            result.extend(plugin.searchUsers(query, props, options, **kw))
        # XXX: Filter on roles
        return result

    # ----------------------------------
    # Private methods
    # ----------------------------------

    def _doAddUser(self, name, password, roles, domains, **kw):
        """Create a new user.

        Finds the first plugin that is not read only, and creates
        the user there. This is here for compability reasons only.
        It's better to call the plugin directly, so you have
        control over where the user is stored.
        """
        plugins = self._get_plugins(IAuthenticationPlugin, include_readonly=0)
        plugins = self._sort_plugins(plugins, self.authentication_order)
        if not plugins: # TODO change to object exception
            raise 'Can not create user. All Authentication plugins are read-only.'
        LOG('PluggableUserFolder', DEBUG, str(plugins))
        return plugins[0]._doAddUser(name, password, roles, domains, **kw)

    def _doChangeUser(self, name, password, roles, domains, **kw):
        """Modify an existing user.

        Only here for compatibility, just as _doAddUser.
        """
        plugins = self._get_plugins(IAuthenticationPlugin, include_readonly=0)
        plugins = self._sort_plugins(plugins, self.authentication_order)
        if not plugins: # TODO change to object exception
            raise 'Can not change user. All Authentication plugins are read-only.'
        return plugins[0]._doChangeUser(name, password, roles, domains, **kw)

    def _doDelUsers(self, names):
        """Delete one or more users.

        Only here for compatibility, just as _doAddUser.
        """
        plugins = self._get_plugins(IAuthenticationPlugin, include_readonly=0)
        plugins = self._sort_plugins(plugins, self.authentication_order)
        if not plugins: # TODO change to object exception
            raise 'Can not delete user(s). All Authentication plugins are read-only.'
        for plugin in plugins:
            localnames = []
            for username in names:
                if plugin.getUser(username):
                    localnames.append(username)
                    names.remove(username) # Only delete from first plugin.
            if localnames:
                plugin._doDelUsers(localnames)

    def _createInitialUser(self):
        """
        If there are no users or only one user in this user folder, populates
        from the 'inituser' file in INSTANCE_HOME.
        We have to do this even when there is already a user just in case the
        initial user ignored the setup messages.
        We don't do it for more than one user to avoid abuse of this mechanism.
        Called only by OFS.Application.initialize().
        """
        if len(self.getUserNames()) >= 1:
            # Don't do this if more than one user
            return
        # FIXME: where does this function come ?
        info = readUserAccessFile('inituser')
        if not info:
            return # No inituser to create
        if len(self._get_plugins(IAuthenticationPlugin,
           include_readonly=0)) == 0:
            # There are only readonly authentication plugins.
            # Create an internal authetication plugin
            try:
                iaplug = InternalAuthenticationPlugin()
                self._setObject(iaplug.getId(), iaplug)
            except ImportError:
                return

        name, password, domains, remote_user_mode = info
        self._doDelUsers(self.getUserNames())
        self._doAddUser(name, password, ('Manager',), domains)
        try:
            os.remove(os.path.join(INSTANCE_HOME, 'inituser'))
        except:
            pass

    # ----------------------------------
    # UserFolder overrides
    # ----------------------------------

    def identify(self, auth):
        LOG('PluggableUserFolder', DEBUG, 'identify()',
        'Auth %s\n' % auth)
        plugins = self._get_plugins(IIdentificationPlugin)
        plugins = self._sort_plugins(plugins, self.identification_order)
        for plugin in plugins:
            if plugin.canIdentify(auth):
                return plugin.identify(auth)

        LOG('PluggableUserFolder', DEBUG, 'identify',
            'No plugins able to identify user\n')
        return None, None

    def validate(self, request, auth='', roles=_noroles):
        LOG('PluggableUserFolder', DEBUG, 'validate()',
        'Roles: %s\nAuth %s\n' % (str(roles), auth))
        plugins = self._get_plugins(IIdentificationPlugin)
        plugins = self._sort_plugins(plugins, self.identification_order)
        for plugin in plugins:
            plugauth = plugin.makeAuthenticationString(request, auth)
            if plugauth is not None:
                break
        # What to do if none of the plugins could make a string?
        # Currently just continue with auth=None. Might not be a good
        # idea, I'm not sure.
        LOG('PluggableUserFolder', DEBUG, 'validate()',
            'Call BasicUserFolder\n')
        u = BasicUserFolder.validate(self, request, plugauth, roles)
        LOG('PluggableUserFolder', DEBUG, 'validate()',
            'Validated User: %s\n' % str(u))
        return u

    def authenticate(self, name, password, request):
        LOG('PluggableUserFolder', DEBUG, 'authenticate()',
            'Username: %s\n' % name)
        super = self._emergency_user
        if name is None:
            return None

        if super and name == super.getUserName():
            user = super
        else:
            # Change from BasicUserFolder.authenticate(),
            # password is passed to getUser():
            user = self.getUser(name, password)

        # Change from BasicUserFolder.authenticate(),
        # check for the user being authenticated by Identify:
        if user is not None and \
            (password is _no_password_check or
             user.authenticate(password, request)):
            LOG('PluggableUserFolder', DEBUG, 'authenticate()',
                'User %s validated\n' % name)
            return user
        else:
            LOG('PluggableUserFolder', DEBUG, 'authenticate()',
                'User %s NOT validated\n' % name)
            return None

    #
    # Login page forwarding support
    #
    def __call__(self, container, req):
        '''The __before_publishing_traverse__ hook.'''
        resp = self.REQUEST['RESPONSE']
        if req.__class__ is not HTTPRequest:
            return
        if not req['REQUEST_METHOD'] in ('HEAD', 'GET', 'PUT', 'POST'):
            return
        if req.environ.has_key('WEBDAV_SOURCE_PORT'):
            return
        if req.get('disable_login_page__', 0):
            return
        # Modify the "unauthorized" response.
        req._hold(ResponseCleanup(resp))
        resp.unauthorized = self.unauthorized
        resp._unauthorized = self._unauthorized

    def _cleanupResponse(self):
        resp = self.REQUEST['RESPONSE']
        # No errors of any sort may propagate, and we don't care *what*
        # they are, even to log them.
        try: del resp.unauthorized
        except: pass
        try: del resp._unauthorized
        except: pass
        return resp

    security.declarePrivate('unauthorized')
    def unauthorized(self):
        resp = self._cleanupResponse()
        # Redirect if desired.
        url = self.getLoginURL()
        if url is not None:
            raise 'Redirect', url
        # Fall through to the standard unauthorized() call.
        resp.unauthorized()

    def _unauthorized(self):
        resp = self._cleanupResponse()
        # If we set the auth cookie before, delete it now.
        # Redirect if desired.
        url = self.getLoginURL()
        if url is not None:
            resp.redirect(url, lock=1)
            # We don't need to raise an exception.
            return
        # Fall through to the standard _unauthorized() call.
        resp._unauthorized()

    security.declarePublic('getLoginURL')
    def getLoginURL(self):
        '''
        Redirects to the login page.
        '''
        if not self.login_page:
            return None

        req = self.REQUEST
        resp = req['RESPONSE']
        if self.login_page.startswith('http://'):
            plugins = self._get_plugins(IIdentificationPlugin)
            plugins = self._sort_plugins(plugins, self.identification_order)
            params = {}
            for each in plugins:
                if hasattr(each, 'getLoginURLParams'):
                    params.update(each.getLoginURLParams(req))
            return '%s?%s' % (self.login_page, urlencode(params))
        else:
            iself = getattr(self, 'aq_inner', self)
            parent = getattr(iself, 'aq_parent', None)
            try:
                page = parent.unrestrictedTraverse(self.login_page)
            except KeyError:
                return None
            came_from = req.get('came_from', None)
            if came_from is None:
                came_from = req['URL']
            retry = getattr(resp, '_auth', 0) and '1' or ''
            url = '%s?came_from=%s&retry=%s&disable_cookie_login__=1' % (
                page.absolute_url(), quote(came_from), retry)
            return url

    def getLogoutURL(self):
        if not self.logout_page:
            return None
        if self.logout_page.startswith('http://'):
            return self.logout_page
        else:
            iself = getattr(self, 'aq_inner', self)
            parent = getattr(iself, 'aq_parent', None)
            try:
                page = parent.unrestrictedTraverse(self.logout_page)
            except KeyError:
                return None
            return page.absolute_url()

    security.declarePublic('logout')
    def logout(self):
        """Log out"""
        plugins = self._get_plugins(IIdentificationPlugin)
        for each in plugins:
            each._logout()

        url = self.getLogoutURL()
        if url:
            self.REQUEST.RESPONSE.redirect(url)

    # Installation and removal of traversal hooks.

    def manage_beforeDelete(self, item, container):
        if item is self:
            handle = self.meta_type + '/' + self.getId()
            BeforeTraverse.unregisterBeforeTraverse(container, handle)

    def manage_afterAdd(self, item, container):
        if item is self:
            handle = self.meta_type + '/' + self.getId()
            container = container.this()
            nc = BeforeTraverse.NameCaller(self.getId())
            BeforeTraverse.registerBeforeTraverse(container, nc, handle)

    security.declareProtected(Permissions.manage_users, 'manage_registerTraverseHook')
    def manage_registerTraverseHook(self, REQUEST):
        """Registers the traverse hook for login page redirection."""
        self.manage_afterAdd(self, self.aq_parent)
        if REQUEST is not None:
            return "TraverseHook Registered"

    security.declarePublic('hasLocalRolesBlocking')
    def hasLocalRolesBlocking(self):
        """Test if local roles blocking is implemented in this user
           folder."""
        return 0 # Nope, it ain't.


def manage_addPluggableUserFolder(self, REQUEST=None):
    """ """
    f = PluggableUserFolder()
    self = self.this()
    if hasattr(aq_base(self), 'acl_users'):
        return MessageDialog(
            title='Item Exists',
            message='This object already contains a User Folder',
            action='%s/manage_main' % REQUEST['URL1'])
    self._setObject('acl_users', f)
    self.__allow_groups__ = f

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url()+'/manage_main')

class ResponseCleanup:
    def __init__(self, resp):
        self.resp = resp

    def __del__(self):
        # Free the references.
        #
        # No errors of any sort may propagate, and we don't care *what*
        # they are, even to log them.
        try: del self.resp.unauthorized
        except: pass
        try: del self.resp._unauthorized
        except: pass
        try: del self.resp
        except: pass
