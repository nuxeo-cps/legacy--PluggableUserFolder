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

from Globals import MessageDialog
from Acquisition import aq_base
from OFS.SimpleItem import SimpleItem

from PluginInterfaces import IAuthenticationPlugin
from Products.LDAPUserFolder.LDAPUserFolder import LDAPUserFolder

class LDAPAuthenticationPlugin(LDAPUserFolder):
    """This plugin stores the user definitions in the ZODB"""
    meta_type = 'LDAP Authentication'
    id = 'ldap_authentication'
    title = 'LDAP Authentication'
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



def manage_addLDAPAuthenticationPlugin(self, REQUEST=None):
    """ """
    ob=LDAPAuthenticationPlugin('LDAP Authentication', 'localhost', '', ''
                , '', [], '', '', '', '', '', '')
    self=self.this()
    if hasattr(aq_base(self), ob.id):
        return MessageDialog(
            title  ='Item Exists',
            message='This object already contains an %s' % id.title ,
            action ='%s/manage_main' % REQUEST['URL1'])
    self._setObject(ob.id, ob)
    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url()+'/manage_main')

