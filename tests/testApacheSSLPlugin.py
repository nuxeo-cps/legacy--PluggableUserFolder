#
# Test Zope's standard UserFolder
#

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

from testUserFolder import TestBase
from Testing.ZopeTestCase import _user_name
from Products.PluggableUserFolder.PluggableUserFolder import _no_password_check
from Products.PluggableUserFolder.ApacheSSLIdentification import \
    ApacheSSLIdentificationPlugin, manage_addApacheSSLIdentificationPlugin

class TestPlugin(TestBase):

    def afterSetUp(self):
        TestBase.afterSetUp(self)
        manage_addApacheSSLIdentificationPlugin(self.folder.acl_users)
        self.plugin = self.folder.acl_users.apache_ssl_identification
        self.app.other = { 'SERVER_URL': 'https://path.to.a.server/index.html' }
        self.app.environ = { self.plugin.ssl_id_source: _user_name }

    def testMakeAuthString(self):
        request = self.app
        authstr = self.plugin.makeAuthenticationString(self.app, None)
        self.failUnless(authstr)
        self.failUnless(self.plugin.canIdentify(authstr))
        name, pwd = self.plugin.identify(authstr)
        self.failUnless(name == _user_name)
        self.failUnless(pwd is _no_password_check)

    def testSSLRequired(self):
        request = self.app
        request.other = {'SERVER_URL': 'http://path.to.a.server/index.html'}
        authstr = self.plugin.makeAuthenticationString(self.app, None)
        self.failUnless(authstr is None)

    def testNotRegisteredUser(self):
        request = self.app
        self.app.environ = { self.plugin.ssl_id_source: 'NotAUser' }
        authstr = self.plugin.makeAuthenticationString(self.app, None)
        self.failUnless(authstr is None)

    def testNoCertificate(self):
        self.app.environ = {}
        authstr = self.plugin.makeAuthenticationString(self.app, None)
        self.failUnless(authstr is None)

    def testNotApacheAuth(self):
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
