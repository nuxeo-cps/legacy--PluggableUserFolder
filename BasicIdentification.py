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

__doc__ = '''Basic Identification Plugin'''
__version__ = '$Revision$'[11:-2]

from zLOG import LOG, DEBUG, ERROR
from base64 import decodestring

from Globals import MessageDialog
from Acquisition import aq_base
from OFS.SimpleItem import SimpleItem

from PluginInterfaces import IIdentificationPlugin

class BasicIdentificationPlugin(SimpleItem):
    """Basic HTTP Authentication support"""
    meta_type = 'Basic Identification'
    id = 'basic_identification'
    title = 'Basic Identification'

    __implements__ = (IIdentificationPlugin,)

    def makeAuthenticationString(self, request, auth):
        if auth and auth.lower().startswith('basic '):
            return auth
        return None

    def canIdentify(self, auth):
        if auth and auth.lower().startswith('basic '):
            return 1
        return 0

    def identify(self, auth):
        try: 
            name, password = tuple(decodestring(
                                   auth.split(' ')[-1]).split(':', 1))
        except:
            raise 'Bad Request', 'Invalid authentication token'
        LOG('BasicIdentification', DEBUG, name)
        return name, password


def manage_addBasicIdentificationPlugin(self, REQUEST=None):
    """ """
    ob = BasicIdentificationPlugin()
    self = self.this()
    if hasattr(aq_base(self), ob.id):
        return MessageDialog(
            title='Item Exists',
            message='This object already contains an %s' % id.title,
            action='%s/manage_main' % REQUEST['URL1'])
    self._setObject(ob.id, ob)
    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url() + '/manage_main')

