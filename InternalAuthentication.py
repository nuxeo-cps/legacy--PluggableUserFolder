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

__doc__='''Internal Authentication Plugin'''
__version__='$Revision$'[11:-2]

#from AccessControl.User import UserFolder
from AccessControl import AuthEncoding
from Globals import DTMLFile
from Acquisition import aq_base
from AccessControl.User import User
from AccessControl.Role import RoleManager, DEFAULTMAXLISTUSERS
from OFS.SimpleItem import SimpleItem
from ZODB.PersistentMapping import PersistentMapping

from PluginInterfaces import IAuthenticationPlugin

class InternalAuthenticationPlugin(SimpleItem):
    """This plugin stores the user definitions in the ZODB"""

    __implements__ = (IAuthenticationPlugin,)
    meta_type = 'Internal Authentication'
    id = 'internal_authentication'
    title = 'Internal Authentication'
    isPrincipiaFolderish=0
    isAUserFolder=0
    maxlistusers = DEFAULTMAXLISTUSERS

    encrypt_passwords = 0

    manage_options=(
        (
        {'label':'Contents', 'action':'manage_main',
         'help':('OFSP','User-Folder_Contents.stx')},
        {'label':'Properties', 'action':'manage_pluginPropertiesForm',
         'help':('OFSP','User-Folder_Properties.stx')},
        )
        +SimpleItem.manage_options
        )

    __ac_permissions__=(
        ('Manage users',
         ('manage_users','getUserNames', 'getUser', 'getUsers',
          'getUserById', 'user_names', 'setDomainAuthenticationMode',
          'userFolderAddUser', 'userFolderEditUser', 'userFolderDelUsers',
          )
         ),
        )

    def isReadOnly(self):
        """Returns 1 if you can not add, change or delete users"""
        return 0

    def __init__(self):
        self.data=PersistentMapping()

    def _isPasswordEncrypted(self, pw):
        return AuthEncoding.is_encrypted(pw)

    def _encryptPassword(self, pw):
        return AuthEncoding.pw_encrypt(pw, 'SSHA')

    #
    # ZMI methods
    #

    def manage_setPluginProperties(self, encrypt_passwords=0,
                                       update_passwords=0,
                                       REQUEST=None):
        """
        Sets the properties of the user folder.
        """
        self.encrypt_passwords = not not encrypt_passwords

        msg = 'Saved changes.'
        changed=0
        if encrypt_passwords and update_passwords:
            changed = 0
            for u in self.getUsers():
                pw = u._getPassword()
                if not self._isPasswordEncrypted(pw):
                    pw = self._encryptPassword(pw)
                    self._doChangeUser(u.getUserName(), pw, u.getRoles(),
                                       u.getDomains())
                    changed = changed + 1

            if not changed:
                msg = 'All passwords already encrypted.'
            else:
                msg = 'Encrypted %d password(s).' % changed

        if REQUEST is not None:
            return self.manage_pluginPropertiesForm(
                REQUEST, manage_tabs_message=msg)
        else:
            return changed

    manage_main=DTMLFile('zmi/mainUser', globals())
    manage_pluginPropertiesForm=DTMLFile('zmi/internalAuthProps', globals())

    #
    # Public API
    #

    def getUserNames(self):
        """Return a list of usernames"""
        names=self.data.keys()
        names.sort()
        return names

    def getUsers(self):
        """Return a list of user objects"""
        data=self.data
        names=data.keys()
        names.sort()
        users=[]
        f=users.append
        for n in names:
            f(data[n])
        return users

    def getUser(self, name):
        """Return the named user object or None"""
        return self.data.get(name, None)

    def _doAddUser(self, name, password, roles, domains, **kw):
        """Create a new user"""
        if password is not None and self.encrypt_passwords:
            password = self._encryptPassword(password)
        self.data[name]=User(name,password,roles,domains)

    def _doChangeUser(self, name, password, roles, domains, **kw):
        user=self.data[name]
        if password is not None:
            if self.encrypt_passwords and not self._isPasswordEncrypted(password):
                password = self._encryptPassword(password)
            user.__=password
        user.roles=roles
        user.domains=domains

    def _doDelUsers(self, names):
        for name in names:
            del self.data[name]


def manage_addInternalAuthenticationPlugin(self, REQUEST=None):
    """ """
    ob=InternalAuthenticationPlugin()
    self=self.this()
    if hasattr(aq_base(self), ob.id):
        return MessageDialog(
            title  ='Item Exists',
            message='This object already contains an %s' % id.title ,
            action ='%s/manage_main' % REQUEST['URL1'])
    self._setObject(ob.id, ob)
    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url()+'/manage_main')

