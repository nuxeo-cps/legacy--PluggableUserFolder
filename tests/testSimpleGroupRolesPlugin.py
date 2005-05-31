#
# Test Zope's standard UserFolder
#

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

from OFS.Folder import Folder

from Testing import ZopeTestCase
from testUserFolder import TestBase
from Interface.Verify import verifyClass

from Testing.ZopeTestCase import _user_name, _folder_name

from Products.PluggableUserFolder.PluginInterfaces import \
    IGroupPlugin
from Products.PluggableUserFolder.SimpleGroupRoles import \
    SimpleGroupRolesPlugin, manage_addSimpleGroupRolesPlugin

from Products.PluggableUserFolder.PluggableUserFolder import \
    manage_addPluggableUserFolder, PluggableUserFolder
from Products.PluggableUserFolder.InternalAuthentication import \
    InternalAuthenticationPlugin
from Products.PluggableUserFolder.PluginInterfaces import \
    IAuthenticationPlugin, IIdentificationPlugin, IRolePlugin
from Products.PluggableUserFolder.BasicIdentification import \
    manage_addBasicIdentificationPlugin
from Products.PluggableUserFolder.SimpleGroupRoles import \
    manage_addSimpleGroupRolesPlugin

def sorted(l):
    l = list(l)
    l.sort()
    return l

class TestBase(ZopeTestCase.ZopeTestCase):

    _setup_fixture = 0

    def afterSetUp(self):
        self._setupFolder()
        manage_addPluggableUserFolder(self.folder)
        self.uf = self.folder.acl_users
        manage_addSimpleGroupRolesPlugin(self.uf)
        self.uf.userFolderAddUser('someuser', 'secret',
            ['SomeRole'], ['somegroup'])

    def beforeClose(self, call_close_hook=1):
        '''Clears out the fixture.'''
        self._logout()
        try: del self.uf
        except AttributeError: pass
        try: del self.folder.acl_users
        except AttributeError: pass
        try: self.app._delObject(_folder_name)
        except (AttributeError, RuntimeError): pass
        try: del self.folder
        except AttributeError: pass
        try: del self._user
        except AttributeError: pass


class TestUserFolder(TestBase):
    '''Test UF is working'''

    def makeFolders(self):
        self.root = Folder('root')
        self.root.fold = Folder('fold')
        self.root.fold.ob = Folder('ob')
        return self.root

    def test_getRolesInContext(self):
        user = self.uf.getUser('someuser')
        root = self.makeFolders()
        fold = root.fold
        ob = fold.ob

        base = ['Authenticated', 'SomeRole']
        self.assertEquals(sorted(user.getRolesInContext(root)), base)
        self.assertEquals(sorted(user.getRolesInContext(fold)), base)
        self.assertEquals(sorted(user.getRolesInContext(ob)), base)

        fold.manage_setLocalRoles('someuser', ['Daddy'])
        self.assertEquals(sorted(user.getRolesInContext(root)), base)
        self.assertEquals(sorted(user.getRolesInContext(fold)),
                          ['Authenticated', 'Daddy', 'SomeRole'])
        self.assertEquals(sorted(user.getRolesInContext(ob)),
                          ['Authenticated', 'Daddy', 'SomeRole'])

        fold.manage_setLocalGroupRoles('somegroup', ['Chief'])
        self.assertEquals(sorted(user.getRolesInContext(root)), base)
        self.assertEquals(sorted(user.getRolesInContext(fold)),
                          ['Authenticated', 'Chief', 'Daddy',
                           'SomeRole'])
        self.assertEquals(sorted(user.getRolesInContext(ob)),
                          ['Authenticated', 'Chief', 'Daddy',
                           'SomeRole'])

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
        suite.addTest(unittest.makeSuite(TestUserFolder))
        return suite

