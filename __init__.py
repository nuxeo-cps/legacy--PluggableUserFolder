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

__doc__ = '''PluggableUserFolder init'''
__version__ = '$Revision$'[11:-2]

from zLOG import LOG, DEBUG
import PluggableUserFolder
import InternalAuthentication
import BasicIdentification
import ApacheSSLIdentification
import CookieIdentification
import GroupRoles
import SimpleGroupRoles

try:
    import LDAPAuthentication
    import LDAPLogin
    LdapSupport = 1
except ImportError:
    LdapSupport = 0

try:
    from Products.CMFCore.DirectoryView import registerDirectory
    registerDirectory('skins', globals())
    CMFSupport = 1
except ImportError:
    CMFSupport = 0

from AccessControl.Permissions import add_user_folders

def initialize(context):
    context.registerClass(
        PluggableUserFolder.PluggableUserFolder,
        permission=add_user_folders,
        constructors=(PluggableUserFolder.manage_addPluggableUserFolder,),
        icon='zmi/UserFolder_icon.gif',
    )
    context.registerClass(
        instance_class=InternalAuthentication.InternalAuthenticationPlugin,
        permission=add_user_folders,
        constructors=(InternalAuthentication.manage_addInternalAuthenticationPlugin,),
        icon='zmi/UserFolder_icon.gif',
        visibility=None,
    )
    context.registerClass(
        instance_class=BasicIdentification.BasicIdentificationPlugin,
        permission=add_user_folders,
        constructors=(BasicIdentification.manage_addBasicIdentificationPlugin,),
        icon='zmi/UserFolder_icon.gif',
        visibility=None,
    )
    context.registerClass(
        instance_class=ApacheSSLIdentification.ApacheSSLIdentificationPlugin,
        permission=add_user_folders,
        constructors=(ApacheSSLIdentification.manage_addApacheSSLIdentificationPlugin,),
        icon='zmi/UserFolder_icon.gif',
        visibility=None,
    )
    context.registerClass(
        instance_class=CookieIdentification.CookieIdentificationPlugin,
        permission=add_user_folders,
        constructors=(CookieIdentification.manage_addCookieIdentificationPlugin,),
        icon='zmi/UserFolder_icon.gif',
        visibility=None,
    )
    context.registerClass(
        instance_class=GroupRoles.GroupRolesPlugin,
        permission=add_user_folders,
        constructors=(GroupRoles.manage_addGroupRolesPlugin,),
        icon='zmi/UserFolder_icon.gif',
        visibility=None,
    )
    registerRolePlugin(GroupRoles.GroupRolesPlugin)
    context.registerClass(
        instance_class=SimpleGroupRoles.SimpleGroupRolesPlugin,
        permission=add_user_folders,
        constructors=(SimpleGroupRoles.manage_addSimpleGroupRolesPlugin,),
        icon='zmi/UserFolder_icon.gif',
        visibility=None,
    )
    registerRolePlugin(SimpleGroupRoles.SimpleGroupRolesPlugin)

    if LdapSupport:
        context.registerClass(
            instance_class=LDAPAuthentication.LDAPAuthenticationPlugin,
            permission=add_user_folders,
            constructors=(LDAPAuthentication.addLDAPAuthenticationPlugin,
                          LDAPAuthentication.manage_addLDAPAuthenticationPlugin,),
            icon='zmi/UserFolder_icon.gif',
            visibility=None,
        )
        context.registerClass(
            instance_class=LDAPLogin.LDAPLoginPlugin,
            permission=add_user_folders,
            constructors=(LDAPLogin.addLDAPLoginPlugin,
                          LDAPLogin.manage_addLDAPLoginPlugin,),
            icon='zmi/UserFolder_icon.gif',
            visibility=None,
        )

from AccessControl.Role import RoleManager, _isNotBeingUsedAsAMethod, \
    _isBeingUsedAsAMethod
from Globals import DTMLFile

def registerRolePlugin(plugin):
    for method in plugin.local_manage_methods:
        uid = 'manage_' + plugin.plugin_id + method['id']
        action = getattr(plugin, method['action'])
        LOG('PluggableFolder', DEBUG, 'Add method on RoleManager',
            'Name: %s \nMethod: <%s>.%s\n' % (uid, plugin.meta_type,
            method['action']))
        setattr(RoleManager, uid, action)

if not hasattr(RoleManager, 'manage_permissions'):
    RoleManager.manage_permissions = RoleManager.manage_access

RoleManager.manage_access = DTMLFile('zmi/security', globals())


# TODO: Make help
#    context.registerHelp()
#    context.registerHelpTitle('Zope Help')

