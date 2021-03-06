#
# Test Zope's standard UserFolder
#

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

from Interface.Verify import verifyClass
from Testing.ZopeTestCase import user_name as _user_name, ZopeLite
from testUserFolder import TestBase
from Products.PluggableUserFolder.PluggableUser import \
    PluggableUser

ZopeLite.installProduct('NuxUserGroups')
ZopeLite.installProduct('CPSDirectory')


class TestUser(TestBase):
    # These tests are mostly here to prove that the full API is supported.
    # Most of the methods are trivial and need no testing per se.
    def testGetRoles(self):
        roles = list(self._user.getRoles())
        roles.sort()
        self.assertEquals(roles, ['Authenticated', 'test_role_1_'])

    def testGetUserName(self):
        self.assertEquals(self._user.getUserName(), _user_name)
    
    def testGetId(self):
        self.assertEquals(self._user.getId(), _user_name)

    def testGetDomains(self):
        self.assertEquals(self._user.getDomains(), ())

    def testGetGroups(self):
        self.assertEquals(self._user.getGroups(), ())
        
    # NB! No property support.
    def testPropertySupport(self):
        # If this changes, the user object must implement
        # full property support.
        self.assertEquals(self.uf.listUserProperties(), ('id', 'roles',))

    def testInterface(self):
        try:
            from Products.CPSDirectory.IUserFolder import IUser
            self.assert_(verifyClass(IUser, PluggableUser))
        except ImportError:
            pass
    
    def testCPSCompliance(self):
        # Add tests here if the user stops working
        # with CPS.
        groups = self._user.getComputedGroups()
        self.assert_('role:Anonymous' in groups, 
            'role:Anonymous not in PluggableUsers groups')
        self.assert_('role:Authenticated' in groups,
            'role:Authenticated not in PluggableUsers groups')
         

if __name__ == '__main__':
    framework(descriptions=0, verbosity=1)
else:
    import unittest
    def test_suite():
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(TestUser))
        return suite

