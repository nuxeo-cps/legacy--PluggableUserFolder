#
# Test Zope's standard UserFolder
#

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

from testUserFolder import TestBase
from Interface.Verify import verifyClass
from Products.PluggableUserFolder.PluginInterfaces import \
    IGroupPlugin
from Products.PluggableUserFolder.SimpleGroupRoles import \
    SimpleGroupRolesPlugin
from Testing.ZopeTestCase import _user_name
from Products.PluggableUserFolder.SimpleGroupRoles import \
    manage_addSimpleGroupRolesPlugin

class TestPlugin(TestBase):

    def testInterface(self):
        self.assert_(verifyClass(IGroupPlugin,
            SimpleGroupRolesPlugin))
        

if __name__ == '__main__':
    framework(descriptions=0, verbosity=1)
else:
    import unittest
    def test_suite():
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(TestPlugin))
        return suite

