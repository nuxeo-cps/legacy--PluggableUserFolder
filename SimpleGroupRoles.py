# Copyright (c) 2003 Nuxeo SARL <http://nuxeo.com>
# Copyright (c) 2003 CEA <http://www.cea.fr>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as published
# by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.
#
# $Id$

__doc__ = '''Internal Authentication Plugin'''
__version__ = '$Revision$'[11:-2]

from PluggableUserFolder import LOG, DEBUG
from Globals import DTMLFile, MessageDialog
from Acquisition import aq_base, aq_inner, aq_parent
from AccessControl import ClassSecurityInfo
from OFS.SimpleItem import SimpleItem
from OFS.Folder import Folder
from OFS.ObjectManager import checkValidId
from ZODB.PersistentList import PersistentList

from PluginInterfaces import IRolePlugin, IGroupPlugin

BadRequestException = 'Bad Request'
ROLEATTRIBUTENAME = '__ac_local_group_roles__'

class SimpleGroup(SimpleItem):

    meta_type = 'Simple Group'
    manage_options = ({'label':'Group', 'action':'manage_groupForm'},) + \
                     SimpleItem.manage_options
    _properties = (
        {'id':'title', 'type': 'string', 'mode': 'w', 'label':'Title'},
        {'id':'members', 'type': 'multiple selection', 'mode': 'w',
            'select_variable': 'getAllUsers','label':'Members'},
        {'id':'global_roles', 'type': 'multiple selection', 'mode': 'w',
            'select_variable': 'valid_roles','label':'Global Roles'},
    )
    manage_groupForm = DTMLFile('zmi/simpleGroupRolesEditGroup', globals())
    manage_main = manage_groupForm
    groups = None

    def __init__(self, id, title):
        self.id = id
        self.title = title
        self.members = PersistentList()
        self.groups = PersistentList()

    #
    # API
    #
    def Title(self):
        return self.title

    def getMembers(self):
        """Returns the members of this group"""
        return tuple(self.members)

    def getUsers(self):
        """Returns all users that are members of this group or subgroup"""
        users = list(self.getMembers())
        groups = []
        for group in self.getGroups():
            if group not in groups:
                plugin = aq_parent(self)
                groupob = plugin.getGroup(group)
                for user in groupob.getMembers():
                    if user not in users:
                        users.append(user)
                groups.append(group)
        LOG('SimpleGroupRoles', DEBUG, str(users))
        return tuple(users)

    def getGroups(self):
        """Returns all groups that are member of this group"""
        if self.groups is None:
            self.groups = PersistentList()
        return tuple(self.groups)

    #
    # UI support functions (called from ZMI)
    #
    def getAllUsers(self):
        """Returns all users available through acl_users"""
        return self.acl_users.getuserids()

    #
    # ZMI methods
    #
    def manage_editSettings(self, title=None, REQUEST=None):
        """Change the settings of the group"""
        if title is not None:
            self.setTitle(title)

        if REQUEST is not None:
            return self.manage_groupForm(manage_tabs_message='Settings changed')

    def setTitle(self, title):
        self.title = title

    def manage_addUsers(self, userids, REQUEST=None):
        """Add a user to the members of the group"""
        # XXX check that user exists
        self.addUsers(userids)
        if REQUEST is not None:
            return self.manage_groupForm(manage_tabs_message='Users added')

    def manage_deleteUsers(self, selectedusers, REQUEST=None):
        """Delete the users in the "selectedusers" list of userids"""
        self.deleteUsers(selectedusers)
        if REQUEST is not None:
            return self.manage_groupForm(manage_tabs_message='Users deleted')

    def addUsers(self, userids):
        for userid in userids:
            if not userid in self.members:
                self.members.append(userid)

    def deleteUsers(self, userids):
        for userid in userids:
            if userid in self.members:
                index = self.members.index(userid)
                del self.members[index]

    def setUsers(self, userids):
        for userid in userids:
            if not userid in self.members:
                self.members.append(userid)
        # Make sure it's a copy we iterate over and not the original
        # list, since we modify the list during the iteration.
        for userid in self.members[:]:
            if not userid in userids:
                index = self.members.index(userid)
                del self.members[index]

    def manage_addGroups(self, groupids, REQUEST=None):
        """Add a user to the members of the group"""
        # XXX check that user exists
        self.addGroups(groupids)
        if REQUEST is not None:
            return self.manage_groupForm(manage_tabs_message='Groups added')

    def manage_deleteGroups(self, selectedgroups, REQUEST=None):
        """Delete the groups in the "selectedgroups" list of group ids"""
        self.deleteGroups(selectedgroups)
        if REQUEST is not None:
            return self.manage_groupForm(manage_tabs_message='Groups deleted')

    def addGroups(self, groupids):
        for groupid in groupids:
            if not groupid in self.groups:
                self.groups.append(groupid)

    def deleteGroups(self, groupids):
        for groupid in groupids:
            if groupid in self.groups:
                index = self.groups.index(groupid)
                del self.groups[index]

    def setGroups(self, groupids):
        for groupid in groupids:
            if not groupid in self.groups:
                self.groups.append(groupid)
        # Make sure it's a copy we iterate over and not the original
        # list, since we modify the list during the iteration.
        for groupid in self.groups[:]:
            if not groupid in groupids:
                index = self.groups.index(groupid)
                del self.groups[index]


class SimpleGroupRolesPlugin(Folder):
    """This plugin stores the user definitions in the ZODB"""
    security = ClassSecurityInfo()
    __implements__ = (IGroupPlugin,IRolePlugin)

    meta_type = 'Simple Group Roles Plugin'
    id = 'simple_groups'
    title = 'Simple Group Roles'
    plugin_id = 'simpleGroupRoles'

    manage_options = ({'label':'Groups', 'action':'manage_groupsForm'},) + \
                     SimpleItem.manage_options

    local_manage_methods = ({'id':'LocalGroups',
                             'label':'Local Groups',
                             'type': 'form',
                             'action':'manage_localGroupsForm'},
                             {'id':'AddGroups',
                             'label':'Add Groups',
                             'type': 'method',
                             'action':'addGroupsOnObject'},
                             {'id':'DeleteGroups',
                             'label':'Delete Groups',
                             'type': 'method',
                             'action':'deleteGroupsOnObject'},
                             {'id':'SetGroupRoles',
                             'label':'Set Group Roles',
                             'type': 'method',
                             'action':'setGroupRolesOnObject'},
                             {'id':'GetGroups',
                             'label':'Get Groups',
                             'type': 'method',
                             'action':'getGroupsOnObject'},
                           )

    #
    # ZMI methods for the GroupPlugin
    #

    manage_groupsForm = DTMLFile('zmi/groupRolesGroups', globals())
    manage_addGroupForm = DTMLFile('zmi/groupRolesAddGroup', globals())
    manage_localGroupsForm = DTMLFile('zmi/simpleGroupRolesLocalGroups', \
        globals())

    def _checkId(self, id):
        if id in ('acl_users', 'group_roles'):
            raise BadRequestException, ('Invalid group name "%s"' % id)
        return checkValidId(self, id)

    def manage_addGroup(self, id, title, REQUEST=None):
        """Adds a new group to the list of groups"""
        self.addGroup(id, title)
        if REQUEST is not None:
            REQUEST['RESPONSE'].redirect(
                self.absolute_url() + '/manage_workspace')

    def manage_delGroups(self, selected, REQUEST):
        """Delete the groups whos id is in the list 'selected'"""
        for id in selected:
            if hasattr(aq_base(self), id):
                self._delObject(id)
        if REQUEST is not None:
            REQUEST['RESPONSE'].redirect(
                self.absolute_url() + '/manage_workspace')

    #
    # ZMI methods patched into RoleManager
    #

    def getGroupsOnObject(self, object=None):
        if object is None:
            object = self
        roledict = getattr(aq_base(object), ROLEATTRIBUTENAME, None)
        if roledict is None:
            return ()
        return roledict.keys()

    def addGroupsOnObject(self, addgroups, roles=(), REQUEST=None):
        """Add groups for local roles on self"""
        roledict = getattr(aq_inner(self), ROLEATTRIBUTENAME, None)
        if roledict is None:
            roledict = {}
        currentgroups = roledict.keys()
        for groupid in addgroups:
            if not groupid in currentgroups:
                roledict[groupid] = roles
        setattr(self, ROLEATTRIBUTENAME, roledict)
        if REQUEST is not None:
            return self.manage_simpleGroupRolesLocalGroups(
                manage_tabs_message='Groups added')


    def deleteGroupsOnObject(self, delgroups, REQUEST=None):
        """Remove groups from the local roles on self"""
        roledict = getattr(aq_base(self), ROLEATTRIBUTENAME)
        if roledict is None:
            return
        currentgroups = roledict.keys()
        for groupid in delgroups:
            if groupid in currentgroups:
                del roledict[groupid]
        setattr(self, ROLEATTRIBUTENAME, roledict)
        if REQUEST is not None:
            return self.manage_simpleGroupRolesLocalGroups(
                manage_tabs_message='Groups added')

    def getGroupRolesOnObject(self, group, object=None):
        if object is None:
            object = self
        attr = getattr(object, ROLEATTRIBUTENAME, {})
        if not attr.has_key(group):
            return []
        return attr[group]

    def setGroupRolesOnObject(self, grouprolesmapping, object=None):
        if object is None:
            object = self
        setattr(object, ROLEATTRIBUTENAME, grouprolesmapping)

    def getAcquiredGroups(self, object):
        result = []
        inner_obj = object
        while 1:
            if hasattr(inner_obj, 'im_self'):
                inner_obj = inner_obj.im_self
            inner = getattr(inner_obj, 'aq_inner', inner_obj)
            parent = getattr(inner, 'aq_parent', None)
            if parent is None:
                break
            inner_obj = parent
            groups = self.getGroupsOnObject(inner_obj)
            if groups:
                result.append({'obj': inner_obj, 'groups': groups})
        return result

    #
    # API
    #
    def getGroupsForUser(self, userid):
        userismemberof = []
        for group in self.getGroups():
            if userid in group.getUsers():
                userismemberof.append(group.getId())
        return userismemberof

    def addGroup(self, id, title):
        self._setObject(id,SimpleGroup(id, title))

    def getGroupIds(self):
        return self.objectIds('Simple Group')

    def getGroups(self):
        return self.objectValues('Simple Group')

    def getGroup(self, id):
        return getattr(self, id, None)

    def getLocalRolesForUser(self, user, object):
        roles = []
        for groupid in self.getGroupsOnObject(object):
            groupob = self.getGroup(groupid)
            if groupob is not None and user in groupob.getUsers():
                roles.extend(self.getGroupRolesOnObject(groupid, object))
        return roles

    def userHasLocalRole(self, user, object, role):
        for groupid in self.getGroupsOnObject(object):
            if role in self.getGroupRolesOnObject(groupid, object):
                groupob = self.getGroup(groupid)
                if user in groupob.getUsers():
                    return 1
        return 0

    def modifyGlobalRoles(self, user, roles):
        # No global role modification
        return roles

    def modifyLocalRoles(self, user, object, roles):
        for role in self.getLocalRolesForUser(user, object):
            if not role in roles:
                roles.append(role)
        return roles

    def isUserAllowed(self, user, object, role, previous):
        # This plugin never removes roles
        if previous:
            return previous
        LOG('GroupRolesPlugin', DEBUG, 'isUserAllowed',
            'User: %s\nRole: %s\nResult: %s\n' % \
            (user, role, str(self.userHasLocalRole(user, object, role))))
        return self.userHasLocalRole(user, object, role)

    def getUsersWithRoles(self, object):
        users = {}
        for group in self.getLocalGroups(object):
            for userid in self.getGroup(group).getUsers():
                users[userid] = 1
        return users.keys()

    def getLocalGroups(self, object):
        result = []
        inner_obj = object
        while 1:
            result.extend(self.getGroupsOnObject(inner_obj))

            if hasattr(inner_obj, 'im_self'):
                inner_obj = inner_obj.im_self
            inner = getattr(inner_obj, 'aq_inner', inner_obj)
            parent = getattr(inner, 'aq_parent', None)
            if parent is None:
                break
            inner_obj = parent

        return result



def manage_addSimpleGroupRolesPlugin(self, REQUEST=None):
    """ """
    ob = SimpleGroupRolesPlugin()
    self = self.this()
    if hasattr(aq_base(self), ob.id):
        return MessageDialog(
            title='Item Exists',
            message='This object already contains an %s' % id.title,
            action='%s/manage_main' % REQUEST['URL1'])
    self._setObject(ob.id, ob)
    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url() + '/manage_main')

