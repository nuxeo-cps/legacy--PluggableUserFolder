#
# Test Zope's standard UserFolder
#

import os, sys
if __name__ == '__main__':
    execfile(os.path.join(sys.path[0], 'framework.py'))

#os.environ['STUPID_LOG_FILE'] = os.path.join(os.getcwd(), 'zLOG.log')
#os.environ['STUPID_LOG_SEVERITY'] = '-200'  # DEBUG

from Interface.Verify import verifyClass
from Testing import ZopeTestCase
from Testing.ZopeTestCase import ZopeLite
from Testing.ZopeTestCase import user_name as _user_name
from Testing.ZopeTestCase import user_role as _user_role
from Testing.ZopeTestCase import folder_name as _folder_name
from Testing.ZopeTestCase import standard_permissions as _standard_permissions
from AccessControl import Unauthorized
from AccessControl.PermissionRole import rolesForPermissionOn
from OFS.DTMLMethod import DTMLMethod
from OFS.Folder import Folder

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

ZopeLite.installProduct('PluggableUserFolder', 1)
# These are installed so that there are products that should
# be filtered out by all_meta_types().
ZopeLite.installProduct('ZCatalog', 1)
ZopeLite.installProduct('PageTemplates', 1)

_pm = 'ThePublishedMethod'

verifyClass

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
        manage_addPluggableUserFolder(self.folder)
        self.uf = self.folder.acl_users
        ob = ReadonlyAuthenticationPlugin()
        self.uf._setObject(ob.id, ob)
        self.uf._addUser(_user_name, 'secret', 'secret', (_user_role,), ())
        self._user = self.uf.getUserById(_user_name).__of__(self.uf)
        self.setPermissions(_standard_permissions)
        manage_addSimpleGroupRolesPlugin(self.uf)

    def beforeTearDown(self):
        '''Clears out the fixture.'''
        self.logout()
        try: del self.uf
        except AttributeError: pass
        try: self.folder._delObject('acl_users')
        except AttributeError: pass
        try: self.app._delObject(_folder_name)
        except (AttributeError, RuntimeError): pass
        try: del self.folder
        except AttributeError: pass
        try: del self._user
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
        object = getattr(object, 'aq_base', object)
        acp = getattr(object, '__ac_permissions__', None)
        if acp is not None:
            if callable(acp):
                acp = acp()
            permission = None
            for key, value in acp:
                if '__call__' in value:
                    permission = key
                    break
            if permission is None:
                return ()
            return rolesForPermissionOn(permission, object)


class TestUserFolder(TestBase):
    '''Test UF is working'''

    def testGetUser(self):
        assert self.uf.getUser(_user_name) is not None

    def testGetUsers(self):
        users = self.uf.getUsers()
        self.assertNotEquals(users, [])
        self.assertEquals(users[0].getUserName(), _user_name)

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
        self.folder.manage_role(_user_role,
            _standard_permissions + ['Add Folders'])
        self.login()
        assert user.has_permission('Add Folders', self.folder)

    def testHasLocalPermission(self):
        user = self.uf.getUser(_user_name)
        self.folder.manage_role('Owner', ['Add Folders'])
        self.folder.manage_addLocalRoles(_user_name, ['Owner'])
        self.login()
        assert user.has_permission('Add Folders', self.folder)

    def testAuthenticate(self):
        user = self.uf.getUser(_user_name)
        assert user.authenticate('secret', self.app.REQUEST)

    def testGetLoginURL1(self):
        self.uf.login_page = 'http://www.somehereelse.com/foo'
        url = self.uf.getLoginURL()
        # There are no params because no plugin that has params is
        # created (that should be tested per plugin)
        self.failUnlessEqual(url, 'http://www.somehereelse.com/foo?')

    def testGetLoginURL2(self):
        ob = DTMLMethod('', __name__='login_page')
        self.folder._setObject('login_page', ob)
        self.uf.login_page = 'login_page'
        url = self.uf.getLoginURL()
        self.failUnlessEqual(url, 'http://nohost/test_folder_1_/login_page?' \
            'came_from=http%3A//nohost&retry=&disable_cookie_login__=1')

        ob = Folder('folder2')
        self.folder._setObject('folder2', ob)
        ob = DTMLMethod('', __name__='login_page')
        self.folder.folder2._setObject('login_page', ob)
        self.uf.login_page = 'folder2/login_page'
        url = self.uf.getLoginURL()
        self.failUnlessEqual(url,
            'http://nohost/test_folder_1_/folder2/login_page?' \
            'came_from=http%3A//nohost&retry=&disable_cookie_login__=1')

        self.uf.login_page = 'nologin_page'
        self.failIf(self.uf.getLoginURL())

    def testGetLogoutURL1(self):
        self.uf.logout_page = 'http://www.somehereelse.com/foo'
        self.failUnlessEqual(self.uf.getLogoutURL(),
            'http://www.somehereelse.com/foo')

    def testGetLogoutURL2(self):
        ob = DTMLMethod('', __name__='logout_page')
        self.folder._setObject('logout_page', ob)
        self.uf.logout_page = 'logout_page'
        url = self.uf.getLogoutURL()
        self.failUnlessEqual(url, 'http://nohost/test_folder_1_/logout_page')

        ob = Folder('folder2')
        self.folder._setObject('folder2', ob)
        ob = DTMLMethod('', __name__='logout_page')
        self.folder.folder2._setObject('logout_page', ob)
        self.uf.logout_page = 'folder2/logout_page'
        url = self.uf.getLogoutURL()
        self.failUnlessEqual(url,
            'http://nohost/test_folder_1_/folder2/logout_page')

        self.uf.logout_page = 'nologout_page'
        self.failIf(self.uf.getLogoutURL())

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
        self.assertEquals(user.getUserName(), _user_name)

    def testNotAuthorize(self):
        # Validate should fail without auth
        request = self.app.REQUEST
        auth = ''
        assert self.uf.validate(request, auth, [_user_role]) is None

    def testNotAuthorize2(self):
        # Validate should fail without roles
        request = self.app.REQUEST
        auth = self._basicAuth(_user_name)
        self.assertEqual(self.uf.validate(request, auth, ()),None)

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
        self.assertNotEquals(user, None)
        self.assertEquals(user.getUserName(), _user_name)

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
        self.assertEquals(len(plugins), 4)

    def testGetAllAuthenticationPlugins(self):
        plugins = self.uf._get_plugins(interface=IAuthenticationPlugin)
        self.assertEquals(len(plugins), 2)

    def testGetWritablePlugins(self):
        plugins = self.uf._get_plugins(include_readonly=0)
        self.assertEquals(len(plugins), 3)

    def testGetWritableAuthenticationPlugins(self):
        plugins = self.uf._get_plugins(interface=IAuthenticationPlugin,
            include_readonly=0)
        self.assertEquals(len(plugins), 1)


class TestInstallFolder(TestBase):

    def testAllMetaTypes(self):
        # Install some other products, so there is stuff to show
        products = self.uf.all_meta_types()
        for product in products:
            isIdPlugin = IIdentificationPlugin in product['interfaces']
            isAuthPlugin = IAuthenticationPlugin in product['interfaces']
            isRolePlugin = IRolePlugin in product['interfaces']
            self.assert_(isIdPlugin or isAuthPlugin or isRolePlugin)

    def testBasicIdPlugin(self):
        # This is used in most tests, and hence pretty well tested.
        # So here are only tests of what doesn't get tested
        # anywhere else.

        # Test the manage_add method.
        self.uf._delObject('basic_identification')
        manage_addBasicIdentificationPlugin(self.uf)
        self.assert_(hasattr(self.uf, 'basic_identification'))

class TestCPSAPI(TestBase):

    def testInterface(self):
        try:
            from Products.CPSDirectory.IUserFolder import IUserFolder
            self.assert_(verifyClass(IUserFolder, PluggableUserFolder))
        except ImportError:
            pass

    def testSearchAPI(self):
        # test_user_1_ is already created. Create some more to test searching.
        self.uf.internal_authentication._addUser(
            'test_user_2_','pass','pass',['Owner'])
        self.uf.internal_authentication._addUser(
            'test_user_3_','pass','pass',['Manager'])
        self.uf.internal_authentication._addUser(
            'never_returned_','pass','pass',['Owner'])
        # Matching id:
        self.assertEquals(self.uf.searchUsers(id='test_user_1_'),
                          ['test_user_1_'])
        # Partial id:
        self.assertEquals(len(self.uf.searchUsers(id='user')), 3)
        # Several ids:
        self.assertEquals(
            len(self.uf.searchUsers(id=['test_user_1_', 'test_user_2_'])),
            2)
        # Roles:
        self.assertEquals(self.uf.searchUsers(roles='Manager'),
                          ['test_user_3_'])
        query = {'id': 'user',
                 'roles': ['Owner', 'Manager']}
        self.assertEquals(self.uf.searchUsers(query=query),
                          ['test_user_2_', 'test_user_3_'])
        # Do a search that returns a properties dict.
        props = ['id', 'roles']
        result = self.uf.searchUsers(query=query, props=props)
        self.assert_(len(result) == 2)
        # Each entry in the result should be a tuple with an id and a dictionary.
        for id, dict in result:
            # Make sure each dict has the properties asked for:
            for prop in props:
                self.assert_(prop in dict.keys())

        # Unsupported keys should mean nothing gets returned:
        query['anotherkey'] = 'shouldnotfail'
        self.assert_(self.uf.searchUsers(query=query) == [])

    def testPropertyGetting(self):
        user = self.uf.getUser('test_user_1_')
        self.assertEqual(user.listProperties(), ['id', 'roles', 'groups'])
        self.assert_(not user.hasProperty('prop'))
        self.assertEqual(user.getProperty('id'), user.getUserName())
        self.assertEqual(user.getProperty('roles'),
                         (_user_role, 'Authenticated'))
        self.assertEqual(user.getProperties(('id','roles')),
                         {'id': 'test_user_1_',
                          'roles': ('test_role_1_', 'Authenticated')})

    def testPropertySetting(self):
        user = self.uf.getUser('test_user_1_')
        self.assert_(not user.setProperty('', ''))
        user.setProperty('roles', [_user_role, 'Manager', 'Owner'])
        self.assertEquals(user.roles, [_user_role, 'Manager', 'Owner'])
        user.setProperties(roles = [_user_role])
        self.assertEquals(user.roles, [_user_role])

    def testCPSRoleAPI(self):
        _user_name2 = 'test_user_2_'
        _user_role2 = 'test_role_2_'
        self.uf.userFolderAddUser(_user_name2, 'pass', [], [])
        self.uf.userFolderAddRole(_user_role2)
        self.uf.setRolesOfUser((_user_role, _user_role2), _user_name)
        self.uf.setUsersOfRole((_user_name, _user_name2), _user_role)
        self.assert_(_user_role2 in self.folder.userdefined_roles())
        roles = list(self.uf.getUser(_user_name).getRoles())
        roles.sort()
        self.assertEquals(roles, ['Authenticated', _user_role, _user_role2])
        owners = self.uf.getUsersOfRole(_user_role)
        owners.sort()
        self.assertEquals(owners, [_user_name, _user_name2])
        f = self.uf.getUsersOfRole(_user_role2)
        self.assertEquals(f, [_user_name])
        self.uf.userFolderDelRoles((_user_role2,))
        self.assert_(_user_role2 not in self.folder.userdefined_roles())


    def testCPSGroupAPI(self):
        _user_name2 = 'test_user_2_'
        _user_group = 'test_group_1_'
        _user_group2 = 'test_group_2_'
        self.uf.userFolderAddUser(_user_name2, 'pass', [], [])
        self.uf.userFolderAddGroup(_user_group)
        self.uf.userFolderAddGroup(_user_group2)
        self.assert_(self.uf.getGroupById(_user_group) is not None)
        groups = list(self.uf.getGroupNames())
        groups.sort()
        self.assert_(groups == [_user_group , _user_group2])
        self.uf.setGroupsOfUser([_user_group, _user_group2], _user_name)
        self.uf.setUsersOfGroup([_user_name2, _user_name], _user_group)
        users = list(self.uf.getGroupById(_user_group).getUsers())
        users.sort()
        self.assert_(users == [_user_name, _user_name2])
        groups = list(self.uf.getUser(_user_name).getGroups())
        groups.sort()
        self.assert_(groups == [_user_group, _user_group2])



if __name__ == '__main__':
    framework(descriptions=0, verbosity=1)
else:
    import unittest
    def test_suite():
        suite = unittest.TestSuite()
        suite.addTest(unittest.makeSuite(TestUserFolder))
        suite.addTest(unittest.makeSuite(TestAccess))
        suite.addTest(unittest.makeSuite(TestPluginFolder))
        suite.addTest(unittest.makeSuite(TestInstallFolder))
        suite.addTest(unittest.makeSuite(TestValidate))
        suite.addTest(unittest.makeSuite(TestCPSAPI))
        return suite

