
import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

from testUserFolder import TestBase
from Testing.ZopeTestCase import _user_name
from Products.PluggableUserFolder.PluggableUserFolder import _no_password_check

class TestPlugin(TestBase):

    def afterSetUp(self):
        TestBase.afterSetUp(self)
        self.plugin = self.folder.acl_users.internal_authentication

    def testSearchAPIString(self):
        # test_user_1_ is already created. Create some more to test searching.
        self.plugin._addUser('test_user_2_','pass','pass',['Owner'])
        self.plugin._addUser('test_user_3_','pass','pass',['Manager'])
        self.plugin._addUser('never_returned_','pass','pass',['Owner'])
        # Matching id:
        self.assert_(self.plugin.searchUsers(id='test_user_1_')
            == ['test_user_1_'])
        # Partisl id:
        self.assert_(len(self.plugin.searchUsers(id='user')) == 3)
        # Several ids:
        self.assert_(len(self.plugin.searchUsers(
            id=['test_user_1_', 'test_user_2_'])) == 2)
        # Roles:
        self.assert_(self.plugin.searchUsers(roles='Manager') ==
            ['test_user_3_'])
        query = { 'id': 'user',
                  'roles': ['Owner', 'Manager']
                }
        self.assert_(self.plugin.searchUsers(query=query) ==
            ['test_user_2_', 'test_user_3_'])
        # Do a search that returns a properties dict.
        props=['id', 'roles']
        result = self.plugin.searchUsers(query=query, props=props)
        self.assert_(len(result) == 2)
        # Each entry in the result should be a tuple with an id and a dictionary.
        for id, dict in result:
            # Make sure each dict has the properties asked for:
            for prop in props:
                self.assert_(prop in dict.keys())

        # Unsupported keys should mean nothing gets returned:
        query['anotherkey'] = 'shouldnotfail'
        self.assert_(self.plugin.searchUsers(query=query) == [])


if __name__ == '__main__':
    framework(descriptions=0, verbosity=1)
else:
    import unittest
    def test_suite():
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(TestPlugin))
        return suite

