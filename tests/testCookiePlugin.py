#
# Test the Cookie Identification plugin
#

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

from testUserFolder import TestBase
from Testing.ZopeTestCase import _user_name
from Products.PluggableUserFolder.PluggableUserFolder import _no_password_check
from Products.PluggableUserFolder.CookieIdentification import \
    CookieIdentificationPlugin, manage_addCookieIdentificationPlugin

def makerequest(app, stdout=sys.stdout):
    '''Just make a fresh request'''
    from ZPublisher.HTTPRequest import HTTPRequest
    from ZPublisher.HTTPResponse import HTTPResponse
    from ZPublisher.BaseRequest import RequestContainer
    resp = HTTPResponse(stdout=stdout)
    environ = {}
    environ['SERVER_NAME'] = _Z2HOST or 'nohost'
    environ['SERVER_PORT'] = '%d' %(_Z2PORT or 80)
    environ['REQUEST_METHOD'] = 'GET'
    return HTTPRequest(sys.stdin, environ, resp)

class TestPlugin(TestBase):

    def afterSetUp(self):
        TestBase.afterSetUp(self)
        manage_addCookieIdentificationPlugin(self.folder.acl_users)
        self.plugin = self.folder.acl_users.cookie_identification
        self.app.REQUEST[self.plugin.name_cookie] = _user_name
        self.app.REQUEST[self.plugin.pw_cookie] = 'secret'

    def testMakeAuthString(self):
        request = self.app
        authstr = self.plugin.makeAuthenticationString(self.app.REQUEST, None)
        self.failUnless(authstr)
        self.failUnless(self.plugin.canIdentify(authstr))
        name, pwd = self.plugin.identify(authstr)
        self.failUnless(name == _user_name)
        self.failUnless(pwd == 'secret')

    def testNotCookieAuth(self):
        self.failIf(self.plugin.canIdentify('basic KJHKJHKJHKHKHKHK'))
        # Note: identify() can raise a 'Bad Request' exception, but these
        # are not object exceptions, so we can't test that.


if __name__ == '__main__':
    framework(descriptions=0, verbosity=1)
else:
    import unittest
    def test_suite():
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(TestPlugin))
        return suite

