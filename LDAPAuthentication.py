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

__doc__ = '''LDAP Authentication Plugin'''
__version__ = ' $Revision$'[11:-2]

from zLOG import LOG, DEBUG, ERROR

from Globals import MessageDialog, DTMLFile
from Acquisition import aq_base, aq_parent
from OFS.SimpleItem import SimpleItem

try:
    from Products.LDAPUserGroupsFolder.LDAPUserFolder import LDAPUserFolder
    from Products.LDAPUserGroupsFolder.LDAPUser import LDAPUser
    _ldap_user_groups = 1
except:
    from Products.LDAPUserFolder.LDAPUserFolder import LDAPUserFolder
    from Products.LDAPUserFolder.LDAPUser import LDAPUser
    _ldap_user_groups = 0

from PluginInterfaces import IAuthenticationPlugin
from PluggableUser import PluggableUserMixin

class PluggableLDAPUser(PluggableUserMixin, LDAPUser):
    def _getProperty(self, id, default=None):
        return LDAPUser.getProperty(self, id, default)

class LDAPAuthenticationPlugin(LDAPUserFolder):
    """This plugin stores the user definitions in the ZODB"""
    meta_type = 'LDAP Authentication'
    title = 'LDAP Authentication'
    isPrincipiaFolderish = 0
    isAUserFolder = 0

    __implements__ = (IAuthenticationPlugin,)

    manage_options = (
        LDAPUserFolder.manage_options[:6]+
        SimpleItem.manage_options
        )

    def isReadOnly(self):
        """Returns 1 if you can not add, change or delete users"""
        return 1

    def getUser(self, name, pwd=None):
        """Return the named user object or None"""
        # All my clever wrapping efforts have failed. We have to
        # resort to pure code duplication. Sigh... /lennart

        if pwd is not None:
            cache_type = 'authenticated'
            cached_user = self._authenticated_cache.get(name, pwd)
        else:
            cache_type = 'anonymous'
            cached_user = self._anonymous_cache.get(name)

        if cached_user:
            if self.verbose > 6:
                msg = 'getUser: "%s" cached in %s cache' % (name, cache_type)
                self._log.log(7, msg)
            return cached_user

        user_roles, user_dn, user_attrs, user_groups = self._lookupuser(uid=name, pwd=pwd)
        if user_dn is None:
            msg = 'getUser: "%s" not found' % name
            self.verbose > 3 and self._log.log(4, msg)
            return None

        if user_attrs is None:
            msg = 'getUser: "%s" has no properties, bailing' % name
            self.verbose > 3 and self._log.log(4, msg)
            return None

        if user_roles is None or user_roles == self._roles:
            msg = 'getUser: "%s" only has roles %s' % (name, str(user_roles))
            self.verbose > 8 and self._log.log(9, msg)

        login_name = user_attrs.get(self._login_attr)
        if self._login_attr != 'dn':
            login_name = login_name[0]

        if _ldap_user_groups:
            user_obj = PluggableLDAPUser( login_name
                            , pwd or 'undef'
                            , user_roles or []
                            , user_groups or []
                            , []
                            , []
                            , user_dn
                            , user_attrs
                            , self.getMappedUserAttrs()
                            , self.getMultivaluedUserAttrs()
                            )
        else:
            user_obj = PluggableLDAPUser( login_name
                            , pwd or 'undef'
                            , user_roles or []
                            , user_groups or []
                            , []
                            , user_dn
                            , user_attrs
                            , self.getMappedUserAttrs()
                            , self.getMultivaluedUserAttrs()
                            )

        if pwd is not None:
            self._authenticated_cache.set(name, user_obj)
        else:
            self._anonymous_cache.set(name, user_obj)

        return user_obj


addLDAPAuthenticationPlugin = DTMLFile('zmi/addLDAPAuthenticationPlugin', \
                              globals())

def manage_addLDAPAuthenticationPlugin(self, id, title, LDAP_server, login_attr
                            , users_base, users_scope, roles, groups_base
                            , groups_scope, binduid, bindpwd, binduid_usage=1
                            , rdn_attr='cn', local_groups=0, use_ssl=0
                            , encryption='SHA', read_only=0, REQUEST=None):
    """ """
    if _ldap_user_groups:
        usergroups_base = usergroups_scope = ''
        ob = LDAPAuthenticationPlugin(title, LDAP_server, login_attr, users_base
                          , users_scope, roles, groups_base, groups_scope
                          , usergroups_base, usergroups_scope
                          , binduid, bindpwd, binduid_usage, rdn_attr
                          , local_groups=local_groups, local_usergroups=1
                          , use_ssl=not not use_ssl
                          , encryption=encryption, read_only=read_only
                          , REQUEST=None)
    else:
        ob = LDAPAuthenticationPlugin(title, LDAP_server, login_attr, users_base
                          , users_scope, roles, groups_base, groups_scope
                          , binduid, bindpwd, binduid_usage, rdn_attr
                          , local_groups=local_groups, use_ssl=not not use_ssl
                          , encryption=encryption, read_only=read_only
                          , REQUEST=None)
    ob.id = id
    self = self.this()
    if hasattr(aq_base(self), id):
        return MessageDialog(
            title  ='Item Exists',
            message='This object already contains an item called %s' % id,
            action ='%s/manage_main' % REQUEST['URL1'])
    self._setObject(id, ob)
    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url()+'/manage_main')

