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
        # Now test the username and password cookies are gone:
        self.failIf(self.app.REQUEST.has_key(self.plugin.name_cookie))
        self.failIf(self.app.REQUEST.has_key(self.plugin.pw_cookie))

        # But there should be an auth cookie with the authstr
        cki = self.app.REQUEST['RESPONSE'].cookies.get(self.plugin.auth_cookie)
        self.failUnless(cki)
        # That cookie should be enugh to reauthenticate. Fake a new request with
        # this cookie
        self.app.REQUEST[self.plugin.auth_cookie] = cki['value']
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

    def testNotRequest(self):
        # Should not accept anything else than real REQUESTs as REQUEST.
        self.failIf(self.plugin.makeAuthenticationString(self.app, None))

    def testNotWebDAV(self):
        self.app.REQUEST.environ['WEBDAV_SOURCE_PORT'] = 'something'
        self.failIf(self.plugin.makeAuthenticationString(self.app.REQUEST, None))

    def testNoName(self):
        self.plugin.delRequestVar(self.app.REQUEST, self.plugin.name_cookie)
        self.failIf(self.plugin.makeAuthenticationString(self.app.REQUEST, None))

    def testNoPass(self):
        self.plugin.delRequestVar(self.app.REQUEST, self.plugin.pw_cookie)
        self.failIf(self.plugin.makeAuthenticationString(self.app.REQUEST, None))

if __name__ == '__main__':
    framework(descriptions=0, verbosity=1)
else:
    import unittest
    def test_suite():
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(TestPlugin))
        return suite

