#
# Test Zope's standard UserFolder
#

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

from Testing import ZopeTestCase
from Testing.ZopeTestCase import _user_name, _user_role, _folder_name, _standard_permissions
from AccessControl import Unauthorized

from Products.PluggableUserFolder.PluggableUserFolder import \
    PluggableUserFolder
from Products.PluggableUserFolder.InternalAuthentication import \
    InternalAuthenticationPlugin
from Products.PluggableUserFolder.PluginInterfaces import \
    IAuthenticationPlugin

_pm = 'ThePublishedMethod'

class ReadonlyAuthenticationPlugin(InternalAuthenticationPlugin):
    """This plugin isn't really read only. It only said it is"""
    meta_type = 'Readonly Authentication'
    id = 'readonly_authentication'
    title = 'Readonly Authentication'

    def isReadOnly(self):
        return 1

class TestBase(ZopeTestCase.ZopeTestCase):

    _setup_fixture = 0

    def afterSetUp(self):
        self._setupFolder()
        self.folder._setObject('acl_users', PluggableUserFolder())
        self.uf = self.folder.acl_users
        ob = ReadonlyAuthenticationPlugin()
        self.uf._setObject(ob.id, ob)
        self.uf._addUser(_user_name, 'secret', 'secret', (_user_role,), ())
        self._user = self.uf.getUserById(_user_name).__of__(self.uf)
        #self.uf.internal_authentication._addUser(_user_name, 'secret', 'secret', (_user_role,), ())
        #self._user = self.uf.internal_authentication.getUserById(_user_name).__of__(self.uf)
        self._setPermissions(_standard_permissions)

    def afterClear(self):
        try: del self.uf
        except AttributeError: pass

    def _setupPublishedMethod(self):
        self.folder.addDTMLMethod(_pm, file='some content')
        pm = self.folder[_pm]
        for p in _standard_permissions:
            pm.manage_permission(p, [_user_role], acquire=0)

    def _setupPublishedRequest(self):
        request = self.app.REQUEST
        request.set('PUBLISHED', self.folder[_pm])
        request.set('PARENTS', [self.folder, self.app])
        request.steps = [_folder_name, _pm]

    def _basicAuth(self, name):
        import base64
        return 'Basic %s' % base64.encodestring('%s:%s' %(name, 'secret'))

    def _call__roles__(self, object):
        # From BaseRequest.traverse()
        roles = ()
        object = getattr(object, 'aq_base', object)
        if hasattr(object, '__call__') and hasattr(object.__call__, '__roles__'):
            roles = object.__call__.__roles__
        return roles


class TestUserFolder(TestBase):
    '''Test UF is working'''

    def testGetUser(self):
        assert self.uf.getUser(_user_name) is not None

    def testGetUsers(self):
        users = self.uf.getUsers()
        assert users != []
        assert users[0].getUserName() == _user_name

    def testGetUserNames(self):
        names = self.uf.getUserNames()
        assert names != []
        assert names[0] == _user_name

    def testIdentify(self):
        auth = self._basicAuth(_user_name)
        name, password = self.uf.identify(auth)
        assert name is not None
        assert name == _user_name
        assert password is not None

    def testGetRoles(self):
        user = self.uf.getUser(_user_name)
        assert _user_role in user.getRoles()
    
    def testGetRolesInContext(self):
        user = self.uf.getUser(_user_name)
        self.folder.manage_addLocalRoles(_user_name, ['Owner'])
        roles = user.getRolesInContext(self.folder)
        assert _user_role in roles
        assert 'Owner' in roles
    
    def testHasRole(self):
        user = self.uf.getUser(_user_name)
        assert user.has_role(_user_role, self.folder)
    
    def testHasLocalRole(self):
        user = self.uf.getUser(_user_name)
        self.folder.manage_addLocalRoles(_user_name, ['Owner'])
        assert user.has_role('Owner', self.folder)
    
    def testHasPermission(self):
        user = self.uf.getUser(_user_name)
        self.folder.manage_role(_user_role, _standard_permissions+['Add Folders'])
        self.login()   # !!!
        assert user.has_permission('Add Folders', self.folder)
    
    def testHasLocalPermission(self):
        user = self.uf.getUser(_user_name)
        self.folder.manage_role('Owner', ['Add Folders'])
        self.folder.manage_addLocalRoles(_user_name, ['Owner'])
        self.login()   # !!!
        assert user.has_permission('Add Folders', self.folder)
    
    def testAuthenticate(self):
        user = self.uf.getUser(_user_name)
        assert user.authenticate('secret', self.app.REQUEST)


class TestAccess(TestBase):
    '''Test UF is protecting access'''

    def afterSetUp(self):
        TestBase.afterSetUp(self)
        self._setupPublishedMethod()
            
    def testAllowAccess(self):
        self.login()
        try:
            self.folder.restrictedTraverse(_pm)
        except Unauthorized:
            self.fail('Unauthorized')

    def testDenyAccess(self):
        self.assertRaises(Unauthorized, self.folder.restrictedTraverse, _pm)


class TestValidate(TestBase):
    '''Test UF is authorizing us'''

    def afterSetUp(self):
        TestBase.afterSetUp(self)
        self._setupPublishedMethod()
        self._setupPublishedRequest()

    def testAuthorize(self):
        # Validate should log us in
        request = self.app.REQUEST
        auth = self._basicAuth(_user_name)
        user = self.uf.validate(request, auth, [_user_role])
        assert user is not None
        assert user.getUserName() == _user_name

    def testNotAuthorize(self):
        # Validate should fail without auth
        request = self.app.REQUEST
        auth = ''
        assert self.uf.validate(request, auth, [_user_role]) is None

    def testNotAuthorize2(self):
        # Validate should fail without roles
        request = self.app.REQUEST
        auth = self._basicAuth(_user_name)
        assert self.uf.validate(request, auth) is None

    def testNotAuthorize3(self):
        # Validate should fail with wrong roles
        request = self.app.REQUEST
        auth = self._basicAuth(_user_name)
        assert self.uf.validate(request, auth, ['Manager']) is None

    def testAuthorize2(self):
        # Validate should allow us to call dm
        request = self.app.REQUEST
        auth = self._basicAuth(_user_name)
        roles = self._call__roles__(self.folder[_pm])
        user = self.uf.validate(request, auth, roles)
        assert user is not None
        assert user.getUserName() == _user_name

    def testNotAuthorize4(self):
        # Validate should deny us to call dm
        request = self.app.REQUEST
        auth = self._basicAuth(_user_name)
        pm = self.folder[_pm]
        for p in _standard_permissions:
            pm.manage_permission(p, [], acquire=0)
        roles = self._call__roles__(pm)
        assert self.uf.validate(request, auth, roles) is None


class TestPluginFolder(TestBase):

    def testGetAllPlugins(self):
        plugins = self.uf._get_plugins()
        self.failUnless(len(plugins) == 2)

    def testGetAllAuthenticationPlugins(self):
        plugins = self.uf._get_plugins(interface=IAuthenticationPlugin)
        self.failUnless(len(plugins) == 2)

    def testGetWritablePlugins(self):
        plugins = self.uf._get_plugins(include_readonly=0)
        self.failUnless(len(plugins) == 1)

    def testGetWritableAuthenticationPlugins(self):
        plugins = self.uf._get_plugins(interface=IAuthenticationPlugin, \
            include_readonly=0)
        self.failUnless(len(plugins) == 1)

    # TODO: Add tests for adding, changing and deleting users to the
    # (deprecated) UserFolder interfaces
    # Add test for _createInitialUser()

# TODO: Create testsuites for each and every plugin used.


if __name__ == '__main__':
    framework(descriptions=0, verbosity=1)
else:
    import unittest
    def test_suite():
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(TestUserFolder))
        suite.addTest(unittest.makeSuite(TestAccess))
        suite.addTest(unittest.makeSuite(TestValidate))
        suite.addTest(unittest.makeSuite(TestPluginFolder))
        return suite

