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

__doc__='''PluggableUserFolder init'''
__version__='$Revision$'[11:-2]

import PluggableUserFolder
import InternalAuthentication
import BasicIdentification
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

# TODO: Make help
#    context.registerHelp()
#    context.registerHelpTitle('Zope Help')

