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

__doc__ = '''Apache SSL Identification Plugin'''
__version__ = '$Revision$'[11:-2]

from Globals import MessageDialog
from zLOG import LOG, DEBUG, ERROR
from base64 import decodestring, encodestring
from Acquisition import aq_base
from AccessControl import ClassSecurityInfo
from OFS.PropertyManager import PropertyManager
from OFS.SimpleItem import SimpleItem

from PluginInterfaces import IIdentificationPlugin
from PluggableUserFolder import _no_password_check

class ApacheSSLIdentificationPlugin(PropertyManager, SimpleItem):
    """This Basic HTTP Authentication support"""
    security = ClassSecurityInfo()

    meta_type = 'Apache SSL Identification'
    id = 'apache_ssl_identification'
    title = 'Apache SSL Identification'

    __implements__ = (IIdentificationPlugin,)

    _properties = ( {'id': 'ssl_id_source',
                     'type': 'string',
                     'label': 'SSL Id Source field',
                     'mode': 'rw',
                    },
                   )
    ssl_id_source = 'SSL_CLIENT_I_DN_CN'

    manage_options = PropertyManager.manage_options + SimpleItem.manage_options

    def makeAuthenticationString(self, request, auth):
        # Make sure this is an SSL request via Apache
        if not request.other['SERVER_URL'].startswith('https://'):
            return None
        ssl_id_source = self.ssl_id_source.strip()
        username = request.environ.get(ssl_id_source)
        LOG('ApacheSSLIdentification', DEBUG, 'makeAuthenticationString',
            'Using %s for Id source\nUsername: %s\n' % (ssl_id_source,username))
        if username is None:
            return None
        user = self.acl_users.getUser(username)
        if user is None:
            # The user in the certificate does not exist
            return None

        password = ''
        ac = encodestring('%s:%s' % (username, password))
        return 'ApacheSSL %s' % ac

    def canIdentify(self, auth):
        if auth and auth.lower().startswith('apachessl '):
            return 1
        return 0

    def identify(self, auth):
        try: 
            name, password = tuple(decodestring(
                                   auth.split(' ')[-1]).split(':', 1))
        except:
            raise 'Bad Request', 'Invalid authentication token'
        return name, _no_password_check #password

    security.declarePublic('propertyLabel')
    def propertyLabel(self, id):
        """Return a label for the given property id
        """
        for p in self._properties:
            if p['id'] == id:
                return p.get('label', id)
        return id


def manage_addApacheSSLIdentificationPlugin(self, REQUEST=None):
    """ """
    ob = ApacheSSLIdentificationPlugin()
    self = self.this()
    if hasattr(aq_base(self), ob.id):
        return MessageDialog(
            title='Item Exists',
            message='This object already contains an %s' % id.title,
            action='%s/manage_main' % REQUEST['URL1'])
    self._setObject(ob.id, ob)
    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url() + '/manage_main')

