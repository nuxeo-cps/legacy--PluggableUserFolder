# (c) 2003 Nuxeo SARL <http://nuxeo.com>
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

__doc__='''Pluggable User Folder'''
__version__='$Revision$'[11:-2]

from zLOG import LOG, DEBUG, ERROR

from Globals import DTMLFile, MessageDialog
from Acquisition import aq_base
from AccessControl.User import BasicUserFolder, UserFolder
from AccessControl.Role import RoleManager, DEFAULTMAXLISTUSERS
from OFS.ObjectManager import ObjectManager
from OFS.SimpleItem import Item

from PluginInterfaces import IAuthenticationPlugin
from Products.PluggableUserFolder.InternalAuthentication import \
    InternalAuthenticationPlugin

_marker=[]

class PluggableUserFolder(ObjectManager, BasicUserFolder):
    meta_type='Pluggable User Folder'
    id       ='acl_users'
    title    ='Pluggable User Folder'

    isPrincipiaFolderish=1
    isAUserFolder=1
    maxlistusers = DEFAULTMAXLISTUSERS

    encrypt_passwords = 0

    manage_options=(
        (
        {'label':'Contents', 'action':'manage_main',
         'help':('OFSP','Folder_View.stx')},
        {'label':'Properties', 'action':'manage_userFolderProperties',
         'help':('OFSP','User-Folder_Properties.stx')},
        )
        +RoleManager.manage_options
        +Item.manage_options
        )

    __ac_permissions__=(
        ('Manage users',
         ('manage_users','getUserNames', 'getUser', 'getUsers',
          'getUserById', 'user_names', 'setDomainAuthenticationMode',
          'userFolderAddUser', 'userFolderEditUser', 'userFolderDelUsers',
          )
         ),
        )

    _product_interfaces = (IAuthenticationPlugin,)

    def __init__(self):
        # As default, add the "Internal" plugins.
        ob=InternalAuthenticationPlugin()
        self._setObject(ob.id, ob)

    def all_meta_types(self, interfaces=None):

        if interfaces is None:
            if hasattr(self, '_product_interfaces'):
                interfaces=self._product_interfaces
            elif hasattr(self, 'aq_acquire'):
                try: interfaces=self.aq_acquire('_product_interfaces')
                except: pass    # Bleah generic pass is bad

        return ObjectManager.all_meta_types(self, interfaces)

    def _subobject_permissions(self):
        return ()

    def _get_plugins(self, interface=None, include_readonly=1):
        result = []
        for plugin in self.objectValues():
            if not include_readonly and plugin.isReadOnly():
                continue
            if interface:
                implements = getattr(plugin, '__implements__', () )
                if not interface in implements:
                    continue
            result.append(plugin)

        return result

    # ----------------------------------
    # ZMI interfaces
    # ----------------------------------

    manage_userFolderProperties = DTMLFile('zmi/userFolderProps', globals())

    # ----------------------------------
    # Public UserFolder object interface
    # ----------------------------------

    def getUserNames(self):
        """Return a list of usernames"""
        result = []
        for plugin in self._get_plugins(IAuthenticationPlugin):
            for username in plugin.getUserNames():
                if username not in result:
                    result.append(username)
        return result

    def getUsers(self):
        """Return a list of user objects"""
        usernames = []
        result = []
        for plugin in self._get_plugins(IAuthenticationPlugin):
            for user in plugin.getUsers():
                if user.getId() not in usernames:
                    usernames.append(user.getId())
                    result.append(user)
        return result

    def getUser(self, name):
        """Return the named user object or None"""
        for plugin in self._get_plugins(IAuthenticationPlugin):
            user = plugin.getUser(name)
            if user:
                return user
        return None

    def _doAddUser(self, name, password, roles, domains, **kw):
        """Create a new user.

         Finds the first plugin that is not read only, and creates
         the user there. This is here for compability reasons only.
         It's better to call the plugin directly, so you have
         control over where the user is stored.
         """
        plugins = self._get_plugins(IAuthenticationPlugin, 0)
        if not plugins:
            raise 'Can not create user. All Authentication plugins are read-only.'
        return plugins[0]._doAddUser(name, password, roles, domains, **kw)

    def _doChangeUser(self, name, password, roles, domains, **kw):
        """Modify an existing user.

        Only here for compatibility, just as _doAddUser.
        """
        plugins = self._get_plugins(IAuthenticationPlugin, 0)
        if not plugins:
            raise 'Can not change user. All Authentication plugins are read-only.'
        return plugins[0]._doChangeUser(name, password, roles, domains, **kw)

    def _doDelUsers(self, names):
        """Delete one or more users.

        Only here for compatibility, just as _doAddUser.
        NB! If one user name exists in several plugins, it will be deleted
        in ALL plugins!
        """
        plugins = self._get_plugins(IAuthenticationPlugin, 0)
        if not plugins:
            raise 'Can not delete user(s). All Authentication plugins are read-only.'
        for plugin in plugins:
            localnames = []
            for username in names:
                if plugin.getUser(name):
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
        if len(self.data) <= 1:
            info = readUserAccessFile('inituser')
            if info:
                name, password, domains, remote_user_mode = info
                self._doDelUsers(self.getUserNames())
                self._doAddUser(name, password, ('Manager',), domains)
                try:
                    os.remove(os.path.join(INSTANCE_HOME, 'inituser'))
                except:
                    pass


def manage_addPluggableUserFolder(self, REQUEST=None):
    """ """
    f=PluggableUserFolder()
    self=self.this()
    if hasattr(aq_base(self), 'acl_users'):
        return MessageDialog(
            title  ='Item Exists',
            message='This object already contains a User Folder',
            action ='%s/manage_main' % REQUEST['URL1'])
    self._setObject('acl_users', f)
    self.__allow_groups__=f

    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url()+'/manage_main')

