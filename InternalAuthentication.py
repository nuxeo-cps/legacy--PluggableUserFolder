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
from Globals import DTMLFile, MessageDialog
from Acquisition import aq_base, aq_parent
from AccessControl import AuthEncoding, ClassSecurityInfo
from AccessControl.User import User, _remote_user_mode
from AccessControl.Role import DEFAULTMAXLISTUSERS
from OFS.SimpleItem import SimpleItem
from ZODB.PersistentMapping import PersistentMapping

from PluginInterfaces import IAuthenticationPlugin

class InternalAuthenticationPlugin(SimpleItem):
    """This plugin stores the user definitions in the ZODB"""
    security = ClassSecurityInfo()

    meta_type = 'Internal Authentication'
    id = 'internal_authentication'
    title = 'Internal Authentication'
    isPrincipiaFolderish=0
    isAUserFolder=0
    maxlistusers = DEFAULTMAXLISTUSERS
    encrypt_passwords = 0

    __implements__ = (IAuthenticationPlugin,)

    manage_options=(
        (
        {'label':'Contents', 'action':'manage_main',
         'help':('OFSP','User-Folder_Contents.stx')},
        {'label':'Properties', 'action':'manage_pluginPropertiesForm',
         'help':('OFSP','User-Folder_Properties.stx')},
        )
        +SimpleItem.manage_options
        )

    #
    # Public API
    #
    def isReadOnly(self):
        """Returns 1 if you can not add, change or delete users"""
        return 0

    def __init__(self):
        self.data=PersistentMapping()

    security.declareProtected('Manage users', 'getUserNames')
    def getUserNames(self):
        """Return a list of usernames"""
        names=self.data.keys()
        names.sort()
        return names

    security.declareProtected('Manage users', 'getUsers')
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

    security.declareProtected('Manage users', 'getUser')
    def getUser(self, name, password=None):
        """Return the named user object or None"""
        return self.data.get(name, None)

    #
    # ZMI methods
    #
    security.declareProtected('Manage users', '_mainUser')
    _mainUser=DTMLFile('zmi/mainUser', globals())
    security.declareProtected('Manage users', '_add_User')
    _add_User=DTMLFile('zmi/addUser', globals(),
                       remote_user_mode__=_remote_user_mode)
    security.declareProtected('Manage users', '_editUser')
    _editUser=DTMLFile('zmi/editUser', globals(),
                       remote_user_mode__=_remote_user_mode)
    security.declareProtected('Manage users', 'manage_main')
    manage=manage_main=_mainUser
    manage_main._setName('manage_main')

    security.declareProtected('Manage users', 'manage_pluginPropertiesForm')
    manage_pluginPropertiesForm=DTMLFile('zmi/internalAuthProps', globals())

    security.declareProtected('Manage users', 'manage_setPluginProperties')
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

    def manage_users(self,submit=None,REQUEST=None,RESPONSE=None):
        """This method handles operations on users for the web based forms
           of the ZMI. Application code (code that is outside of the forms
           that implement the UI of a user folder) are encouraged to use
           manage_std_addUser"""
        if submit=='Add...':
            return self._add_User(self, REQUEST)

        if submit=='Edit':
            try:    user=self.getUser(REQUEST.get('name'))
            except: return MessageDialog(
                    title  ='Illegal value',
                    message='The specified user does not exist',
                    action ='manage_main')
            return self._editUser(self,REQUEST,user=user,password=user.__)

        if submit=='Add':
            name    =REQUEST.get('name')
            password=REQUEST.get('password')
            confirm =REQUEST.get('confirm')
            roles   =REQUEST.get('roles')
            domains =REQUEST.get('domains')
            return self._addUser(name,password,confirm,roles,domains,REQUEST)

        if submit=='Change':
            name    =REQUEST.get('name')
            password=REQUEST.get('password')
            confirm =REQUEST.get('confirm')
            roles   =REQUEST.get('roles')
            domains =REQUEST.get('domains')
            return self._changeUser(name,password,confirm,roles,
                                    domains,REQUEST)

        if submit=='Delete':
            names=REQUEST.get('names')
            return self._delUsers(names,REQUEST)

        return self.manage_main(self, REQUEST)

    #
    # Internal API
    #
    def _isPasswordEncrypted(self, pw):
        return AuthEncoding.is_encrypted(pw)

    def _encryptPassword(self, pw):
        return AuthEncoding.pw_encrypt(pw, 'SSHA')

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

    def _addUser(self,name,password,confirm,roles,domains,REQUEST=None):
        if not name:
            return MessageDialog(
                   title  ='Illegal value',
                   message='A username must be specified',
                   action ='manage_main')
        if not password or not confirm:
            if not domains:
                return MessageDialog(
                   title  ='Illegal value',
                   message='Password and confirmation must be specified',
                   action ='manage_main')
        if self.getUser(name) or (aq_parent(self)._emergency_user and
                                  name == aq_parent(self)._emergency_user.getUserName()):
            return MessageDialog(
                   title  ='Illegal value',
                   message='A user with the specified name already exists',
                   action ='manage_main')
        if (password or confirm) and (password != confirm):
            return MessageDialog(
                   title  ='Illegal value',
                   message='Password and confirmation do not match',
                   action ='manage_main')

        if not roles: roles=[]
        if not domains: domains=[]

        if domains and not self.domainSpecValidate(domains):
            return MessageDialog(
                   title  ='Illegal value',
                   message='Illegal domain specification',
                   action ='manage_main')
        self._doAddUser(name, password, roles, domains)
        if REQUEST: return self._mainUser(self, REQUEST)


    def _changeUser(self,name,password,confirm,roles,domains,REQUEST=None):
        if password == 'password' and confirm == 'pconfirm':
            # Protocol for editUser.dtml to indicate unchanged password
            password = confirm = None
        if not name:
            return MessageDialog(
                   title  ='Illegal value',
                   message='A username must be specified',
                   action ='manage_main')
        if password == confirm == '':
            if not domains:
                return MessageDialog(
                   title  ='Illegal value',
                   message='Password and confirmation must be specified',
                   action ='manage_main')
        if not self.getUser(name):
            return MessageDialog(
                   title  ='Illegal value',
                   message='Unknown user',
                   action ='manage_main')
        if (password or confirm) and (password != confirm):
            return MessageDialog(
                   title  ='Illegal value',
                   message='Password and confirmation do not match',
                   action ='manage_main')

        if not roles: roles=[]
        if not domains: domains=[]

        if domains and not self.domainSpecValidate(domains):
            return MessageDialog(
                   title  ='Illegal value',
                   message='Illegal domain specification',
                   action ='manage_main')
        self._doChangeUser(name, password, roles, domains)
        if REQUEST: return self._mainUser(self, REQUEST)

    def _delUsers(self,names,REQUEST=None):
        if not names:
            return MessageDialog(
                   title  ='Illegal value',
                   message='No users specified',
                   action ='manage_main')
        self._doDelUsers(names)
        if REQUEST: return self._mainUser(self, REQUEST)


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

