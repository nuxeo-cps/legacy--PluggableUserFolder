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

from AccessControl.User import UserFolder
from Acquisition import aq_base

from PluginInterfaces import IAuthenticationPlugin


class InternalAuthenticationPlugin(UserFolder):
    """This plugin stores the user definitions in the ZODB"""

    __implements__ = (IAuthenticationPlugin,)
    meta_type = 'Internal Authentication'
    id = 'internal_authentication'
    title = 'Internal Authentication'

    def isReadOnly(self):
        """Returns 1 if you can not add, change or delete users"""
        return 0

    # TODO: Clear of 'excess baggage' by not just subclassing a
    # standard user folder.


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

