#
# Test Zope's standard UserFolder
#

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

from Testing.ZopeTestCase import _user_name, ZopeLite
from AccessControl import Unauthorized
from testUserFolder import TestBase

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
        self.assertEquals(self._user.getDomains(), () )

    def testGetGroups(self):
        self.assertEquals(self._user.getGroups(), () )
        
    # NB! No property support.
    def testPropertySupport(self):
        # If this changes, the user object must implement
        # full property support.
        self.assertEquals(self.uf.listUserProperties(), 
            ('id', 'roles', 'groups') )
        

    
if __name__ == '__main__':
    framework(descriptions=0, verbosity=1)
else:
    import unittest
    def test_suite():
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(TestUser))
        return suite

