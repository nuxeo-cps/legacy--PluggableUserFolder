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

__doc__='''LDAP Authentication Plugin'''
__version__='$Revision$'[11:-2]

from zLOG import LOG, DEBUG, ERROR

from Globals import MessageDialog, DTMLFile
from Acquisition import aq_base
from OFS.SimpleItem import SimpleItem

from PluginInterfaces import IAuthenticationPlugin
from Products.LDAPUserFolder.LDAPUserFolder import LDAPUserFolder

class LDAPLoginPlugin(LDAPUserFolder):
    """This plugin stores the user definitions in the ZODB"""
    meta_type = 'LDAP Login'
    title = 'LDAP Login'
    isPrincipiaFolderish=0
    isAUserFolder=0

    __implements__ = (IAuthenticationPlugin,)

    manage_options=(
        LDAPUserFolder.manage_options[:6]+
        SimpleItem.manage_options
        )

    def isReadOnly(self):
        """Returns 1 if you can not add, change or delete users"""
        return 1

    def getUserNames(self):
        return []

    def getUsers(self, authenticated=None):
        if authenticated==1:
            return LDAPUserFolder.getUsers(self,authenticated)
        return []

    def getUser(self, name, password=None):
        LOG('LDAP Login', DEBUG, 'getUser',
            'Username: %s\nPassword: %s\n' % (name, password))
        if password is None:
            return None
        elif self.acl_users.getUser(name) is None:
            # This user is  not defined anywhere in the UserFolder
            return None
        else:
            return LDAPUserFolder.getUser(self, name, password)


addLDAPLoginPlugin = DTMLFile('zmi/addLDAPLoginPlugin', globals())

def manage_addLDAPLoginPlugin(self, id, title, LDAP_server, login_attr
                            , users_base, users_scope, roles, groups_base
                            , groups_scope, binduid, bindpwd, binduid_usage=1
                            , rdn_attr='cn', local_groups=0, use_ssl=0
                            , encryption='SHA', read_only=0, REQUEST=None
                            ):
    """ """
    ob=LDAPLoginPlugin(title, LDAP_server, login_attr, users_base, users_scope
                          , roles, groups_base, groups_scope, binduid, bindpwd
                          , binduid_usage, rdn_attr, local_groups=local_groups
                          , use_ssl=not not use_ssl, encryption=encryption
                          , read_only=read_only, REQUEST=None)
    ob.id = id
    self=self.this()
    if hasattr(aq_base(self), id):
        return MessageDialog(
            title  ='Item Exists',
            message='This object already contains an item called %s' % id,
            action ='%s/manage_main' % REQUEST['URL1'])
    self._setObject(id, ob)
    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url()+'/manage_main')

