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

__doc__ = '''Apache SSL Identification Plugin'''
__version__ = '$Revision$'[11:-2]

from urllib import quote, unquote

from PluggableUserFolder import LOG, DEBUG, ERROR
from Globals import MessageDialog
from base64 import decodestring, encodestring
from Acquisition import aq_base
from AccessControl import ClassSecurityInfo
from OFS.PropertyManager import PropertyManager
from OFS.SimpleItem import SimpleItem
from ZPublisher.HTTPRequest import HTTPRequest

from PluginInterfaces import IIdentificationPlugin

class CookieIdentificationPlugin(PropertyManager, SimpleItem):
    """This Basic HTTP Authentication support"""
    security = ClassSecurityInfo()

    meta_type = 'Cookie Identification'
    id = 'cookie_identification'
    title = 'Cookie Identification'

    __implements__ = (IIdentificationPlugin,)

    _properties = ({'id':'auth_cookie', 'type': 'string', 'mode':'w',
                    'label':'Authentication cookie name'},
                   {'id':'name_cookie', 'type': 'string', 'mode':'w',
                    'label':'User name form variable'},
                   {'id':'pw_cookie', 'type': 'string', 'mode':'w',
                    'label':'User password form variable'},
                   )

    auth_cookie = '__ac'
    name_cookie = '__ac_name'
    pw_cookie = '__ac_password'

    manage_options = PropertyManager.manage_options + SimpleItem.manage_options

    #
    # Public API
    #

    def makeAuthenticationString(self, request, auth):
        if not isinstance(request, HTTPRequest):
            LOG('CookieIdentification', DEBUG, 'Not an HTTP Request')
            return None

        # XXX: what if it is a HEAD ?
        if not request['REQUEST_METHOD'] in ('GET', 'PUT', 'POST'):
            LOG('CookieIdentification', DEBUG, 'Not a GET, PUT or POST')
            return None

        # WebDAV isn't supported because there is no way to set the cookies, since
        # you need a login web page to set them.
        if request.environ.has_key('WEBDAV_SOURCE_PORT'):
            LOG('CookieIdentification', DEBUG, 'WebDAV not supported')
            return None

        if request.has_key(self.pw_cookie) \
          and request.has_key(self.name_cookie):
            # Attempt to log in and set cookies.
            name = request[self.name_cookie]
            pw = request[self.pw_cookie]
            ac = encodestring('%s:%s' % (name, pw))
            response = request['RESPONSE']
            LOG('CookieIdentification', DEBUG, 'New cookie login', ac+'\n')
            response.setCookie(self.auth_cookie, quote(ac) , path='/')
            #self.delRequestVar(request, self.name_cookie)
            #self.delRequestVar(request, self.pw_cookie)
            #request._auth = 'CookieAuth %s' % ac
            #return request._auth
            return 'CookieAuth %s' % ac
        if request.has_key(self.auth_cookie):
            ac = unquote(request[self.auth_cookie])
            #self.delRequestVar(req, self.auth_cookie)
            LOG('CookieIdentification', DEBUG, 'Found cookie login', ac+'\n')
            return 'CookieAuth %s' % ac
        return None

    def canIdentify(self, auth):
        if auth and auth.lower().startswith('cookieauth '):
            LOG('CookieIdentification', DEBUG, 'CAN identify', auth + '\n')
            return 1
        LOG('CookieIdentification', DEBUG, 'Can NOT identify', str(auth) + '\n')
        return 0

    def identify(self, auth):
        try: 
            name, password = tuple(decodestring(
                                   auth.split(' ')[-1]).split(':', 1))
        except:
            raise 'Bad Request', 'Invalid authentication token'
        LOG('CookieIdentification', DEBUG, 'Identify',
            'User: %s\nPass: %s\n' % (name, password))
        return name, password

    security.declarePublic('logout')
    def logout(self):
        '''Log out the user and redirect to the logout page.'''
        req = self.REQUEST
        resp = req['RESPONSE']
        resp.expireCookie(self.auth_cookie, path='/')
        # XXX No redirect is done. Check with CookieCrimbler


    #
    # Internal methods
    #
    security.declarePublic('propertyLabel')
    def propertyLabel(self, id):
        """Return a label for the given property id."""
        for p in self._properties:
            if p['id'] == id:
                return p.get('label', id)
        return id

    security.declarePrivate('delRequestVar')
    def delRequestVar(self, req, name):
        # No errors of any sort may propagate, and we don't care *what*
        # they are, even to log them.
        try: del req.other[name]
        except: pass
        try: del req.form[name]
        except: pass
        try: del req.cookies[name]
        except: pass
        try: del req.environ[name]
        except: pass


def manage_addCookieIdentificationPlugin(self, REQUEST=None):
    """ """
    ob = CookieIdentificationPlugin()
    self = self.this()
    if hasattr(aq_base(self), ob.id):
        return MessageDialog(
            title='Item Exists',
            message='This object already contains an %s' % id.title,
            action='%s/manage_main' % REQUEST['URL1'])
    self._setObject(ob.id, ob)
    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url() + '/manage_main')

