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
if os.environ.get("ZOPE_PLUGGABLE_LOGGING", None) == "OFF":
    def LOG(*args, **kw):
        pass

from Globals import DTMLFile, MessageDialog
from Acquisition import aq_base
from AccessControl import ClassSecurityInfo, Permissions
from AccessControl.User import BasicUserFolder, _noroles
from AccessControl.Role import RoleManager, DEFAULTMAXLISTUSERS
from AccessControl.PermissionRole import rolesForPermissionOn

from OFS.ObjectManager import ObjectManager
from OFS.SimpleItem import Item

from PluginInterfaces import IAuthenticationPlugin, IIdentificationPlugin, \
    IRolePlugin, IGroupPlugin
from InternalAuthentication import InternalAuthenticationPlugin
from BasicIdentification import BasicIdentificationPlugin

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

    encrypt_passwords = 0

    manage_options = (
        (
        {'label':'Contents', 'action':'manage_main',
         'help':('OFSP','Folder_View.stx')},
        {'label':'Properties', 'action':'manage_userFolderProperties',
         'help':('OFSP','User-Folder_Properties.stx')},
        )
        +RoleManager.manage_options
        +Item.manage_options
        )

    _product_interfaces = (IAuthenticationPlugin, IIdentificationPlugin, \
                           IRolePlugin, IGroupPlugin)

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
                try: interfaces = self.aq_acquire('_product_interfaces')
                except: pass    # Bleah generic pass is bad

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
            order = self.identificatio_order
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
                   and plugin.isReadonly():
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

    security.declareProtected(Permissions.manage_users, \
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
                message = message + 'Error: Plugin %s not found\n' % plug
                error = 1
        if not error:
            for plug in existing_plugs:
                message = message + \
                'Plugin %s not included in list, appending.\n' % plug
                plugs.append(plug)
        return plugs, message, error

    def manage_setUserFolderProperties(self, maxlistusers=DEFAULTMAXLISTUSERS,
                                       identification_order='',
                                       authentication_order='',
                                       group_role_order='',
                                       REQUEST=None):
        """
        Sets the properties of the user folder.
        """
        message = ''
        error = 0
        iplugs, msg, err = self._munge_order(identification_order, \
                                             IIdentificationPlugin)
        message = message + msg
        if err:
            error = 1

        aplugs, msg, err = self._munge_order(authentication_order, \
                                             IAuthenticationPlugin)
        message = message + msg
        if err:
            error = 1

        gplugs, msg, err = self._munge_order(group_role_order, \
                                             IGroupPlugin)
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
                # To get to the role plugins, we need to make sure the
                # user knows where the user folder is:
                user._v_acl_users = self
                return user
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
        pass

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

    def getGroupsForUser(self, userid):
        ismemberof = []
        for plugin in self._get_plugins(IRolePlugin):
            ismemberof.extend(plugin.getGroupsForUser(userid))
        LOG('PluggableUserFolder', DEBUG, 'getGroupsForUser',
            str(ismemberof)+'\n')
        return ismemberof

    # Roles plugin support
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

    def mergedLocalRoles(self, object, withgroups=0, withpath=0):
        """Returns all local roles valid for an object"""
        # withgroups and widthpath is there fore CPS compatibility reasons
        # they are currently ignored
        LOG('PluggableUserFolder', -199, 'mergedLocalRoles()')
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

        # deal with groups
        plugins = self._get_plugins(IRolePlugin)
        for plugin in plugins:
            for user in plugin.getUsersWithRoles():
                if user not in merged.keys():
                    merged[user] = {}

        for user, roles in merged.items():
            merged[user] = roles.keys()
        for plugin in plugins:
            for user in merged.keys():
                merged[user] = plugin.modifyLocalRoles(user, object,
                                    merged[user])

        return merged

    def _allowedRolesAndUsers(self, ob):
        """
        Return a list of roles, users and groups with View permission.
        Used by PortalCatalog to filter out items you're not allowed to see.
        """
        allowed = {}
        for r in rolesForPermissionOn('View', ob):
            allowed[r] = 1
        localroles = self.mergedLocalRoles(ob, withgroups=1) # groups
        for user_or_group, roles in localroles.items():
            for role in roles:
                if allowed.has_key(role):
                    allowed[user_or_group] = 1
        if allowed.has_key('Owner'):
            del allowed['Owner']
        return list(allowed.keys())

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
        NB! If one user name exists in several plugins, it will be deleted
        in ALL plugins!
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
            plugin._doDelUsers(localnames)

    def _createInitialUser(self):
        """
        If there are no users or only one user in this user folder,
        populates from the 'inituser' file in INSTANCE_HOME.
        We have to do this even when there is already a user
        just in case the initial user ignored the setup messages.
        We don't do it for more than one user to avoid
        abuse of this mechanism.
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
        plugins = self._get_plugins(IIdentificationPlugin)
        plugins = self._sort_plugins(plugins, self.identification_order)
        for plugin in plugins:
            if plugin.canIdentify(auth):
                return plugin.identify(auth)

        LOG('PluggableUserFolder', ERROR, 'identify',
            'No plugins able to identify user\n')
        return None, None

    def validate(self, request, auth='', roles=_noroles):
        LOG('PluggableUseFolder', DEBUG, 'validate()',
        'Roles: %s\n' % str(roles))
        plugins = self._get_plugins(IIdentificationPlugin)
        plugins = self._sort_plugins(plugins, self.identification_order)
        for plugin in plugins:
            auth = plugin.makeAuthenticationString(request, auth)
            if auth is not None:
                break
        # What to do if none of the plugins could make a string?
        # Currently just continue with auth=None. Might not be a good
        # idea, I'm not sure.
        LOG('PluggableUserFolder', DEBUG, 'validate()',
            'Call BasicUserFolder\n')
        u = BasicUserFolder.validate(self, request, auth, roles)
        LOG('PluggableUserFolder', DEBUG, 'validate()',
            'Validated User: %s\n' % str(u))
        return u

    def authenticate(self, name, password, request):
        LOG('PluggableUserFolder', DEBUG, 'authenticate()',
            'Username: %s\nPassword %s\n' % (name, password))
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
            (password is _no_password_check or \
             user.authenticate(password, request)):
            LOG('PluggableUserFolder', DEBUG, 'authenticate()',
                'User %s validated\n' % name)
            return user
        else:
            LOG('PluggableUserFolder', DEBUG, 'authenticate()',
                'User %s NOT validated\n' % name)
            return None


def manage_addPluggableUserFolder(self, REQUEST=None):
    """ """
    f = PluggableUserFolder()
    self = self.this()
    if hasattr(aq_base(self), 'acl_users'):
        return MessageDialog(
            title  ='Item Exists',
            message='This object already contains a User Folder',
            action ='%s/manage_main' % REQUEST['URL1'])
    self._setObject('acl_users', f)
    self.__allow_groups__ = f

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url()+'/manage_main')

