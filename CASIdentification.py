# Copyright (c) 2004 Nuxeo SARL <http://nuxeo.com>
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

__doc__ = '''CAS Identification Plugin'''
__version__ = '$Revision$'[11:-2]

import urllib

from Globals import MessageDialog
from zLOG import LOG, DEBUG, ERROR
from base64 import decodestring, encodestring
from Acquisition import aq_base
from AccessControl import ClassSecurityInfo
from OFS.PropertyManager import PropertyManager
from OFS.SimpleItem import SimpleItem

from PluginInterfaces import IIdentificationPlugin
from PluggableUserFolder import _no_password_check

class CASIdentificationPlugin(PropertyManager, SimpleItem):
    """Yale ITS Central Authentication Service support"""
    security = ClassSecurityInfo()

    meta_type = 'CAS Identification'
    id = 'cas_identification'
    title = 'CAS Identification'

    __implements__ = (IIdentificationPlugin,)

    _properties = ( {'id': 'login_url',
                     'type': 'string',
                     'label': 'Login page URL',
                     'mode': 'rw',
                    },
                    {'id': 'validate_url',
                     'type': 'string',
                     'label': 'Ticket validation URL',
                     'mode': 'rw',
                    },                    
                    {'id': 'session_var',
                     'type': 'string',
                     'label': 'Session varible ID',
                     'mode': 'rw',
                    },                    
                   )
    login_url = ''
    validate_url = ''
    session_var = '__ac_cas_username'

    manage_options = PropertyManager.manage_options + SimpleItem.manage_options

    def makeAuthenticationString(self, request, auth):
        session = request.SESSION
        username = getattr(session, self.session_var, None)
        if username is None: 
            # Not already authenticated. Is there a ticket in the URL?
            ticket = request.form.get('ticket')
            if ticket is None:
                return None # No CAS authentification
            username = self.validateTicket(request['URL'], ticket)
            if username is None:
                return None # Invalid CAS ticket
            
            # Successfult CAS authentication. 
            setattr(session, self.session_var, username)
            
        LOG('CASIdentification', DEBUG, 'makeAuthenticationString',
            'Username: %s\n' % (username))
        
        user = self.acl_users.getUser(username)
        if user is None:
            # The user in the certificate does not exist
            return None

        ac = encodestring(username + ':')
        return 'CAS %s' % ac

    def canIdentify(self, auth):
        if auth and auth.lower().startswith('cas '):
            return 1
        return 0

    def identify(self, auth):
        try: 
            name, password = tuple(decodestring(
                                   auth.split(' ')[-1]).split(':', 1))
        except: #TODO: Check what kind of exceptions can happen here.
                #Bad request exceptions must be non-object exceptions.
            raise 'Bad Request', 'Invalid authentication token'
        return name, _no_password_check

    security.declarePublic('propertyLabel')
    def propertyLabel(self, id):
        """Return a label for the given property id
        """
        for p in self._properties:
            if p['id'] == id:
                return p.get('label', id)
        return id

    def _logout(self):
        session = self.REQUEST.SESSION
        delattr(session, self.session_var)

    def getLoginURLParams(self, request):
        came_from = request.get('came_from', None)
        if came_from is None:
            came_from = request['URL']
        # TODO: Add request parameters?
        return {'service': came_from}
        
    def validateTicket(self, service, ticket):
        # prepare the GET parameters for checking the login
        checkparams = "?service=" + service + "&ticket=" + ticket
        # check the ticket
        casdata = urllib.URLopener().open(self.validate_url + checkparams)
        test = casdata.readline().strip()
        if test == 'yes':
            # user is validated
            username = casdata.readline().strip()
            return username
        else:
            # some unknown authentication error occurred
            return None
    

def manage_addCASIdentificationPlugin(self, REQUEST=None):
    """ """
    ob = CASIdentificationPlugin()
    self = self.this()
    if hasattr(aq_base(self), ob.id):
        return MessageDialog(
            title='Item Exists',
            message='This object already contains an %s' % id.title,
            action='%s/manage_main' % REQUEST['URL1'])
    self._setObject(ob.id, ob)
    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url() + '/manage_main')

