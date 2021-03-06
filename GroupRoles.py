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

from zLOG import LOG, DEBUG
from Globals import DTMLFile, MessageDialog
from Acquisition import aq_base
from AccessControl import ClassSecurityInfo
from OFS.SimpleItem import SimpleItem
from OFS.Folder import Folder
from OFS.ObjectManager import checkValidId
from Globals import PersistentMapping

from PluginInterfaces import IRolePlugin, IGroupPlugin

BadRequestException = 'Bad Request'

class Group(SimpleItem):

    meta_type = 'Group'
    global_roles = []
    manage_options = ({'label':'Group', 'action':'manage_groupForm'},) + \
                     SimpleItem.manage_options
    _properties = (
        {'id':'title', 'type': 'string', 'mode': 'w', 'label':'Title'},
        {'id':'members', 'type': 'multiple selection', 'mode': 'w',
            'select_variable': 'getAllUsers','label':'Members'},
        {'id':'global_roles', 'type': 'multiple selection', 'mode': 'w',
            'select_variable': 'valid_roles','label':'Global Roles'},
    )
    manage_groupForm = DTMLFile('zmi/groupRolesEditGroup', globals())
    manage_main = manage_groupForm

    def __init__(self, id, title):
        self.id = id
        self.title = title
        self.members = PersistentMapping()
        self.global_roles = []

    #
    # API
    #

    def getUsers(self):
        return self.members.keys()

    def Title(self):
        return self.title

    def getMemberRoles(self, userid):
        if userid in self.members.keys():
            return self.members[userid]
        return []

    def setMemberRoles(self, userid, roles):
        self.members[userid] = roles
    #
    # UI support functions (called from ZMI)
    #
    def getAllUsers(self):
        """Returns all users available through acl_users"""
        return self.acl_users.getuserids()

    def userHasRole(self, user, role):
        """Checks for a certain role mapping

        Mainly used to set a check box in the ZMI
        """
        return self.members.has_key(user) and role in self.members[user]


    #
    # ZMI methods
    #
    def manage_editSettings(self, title=None, REQUEST=None):
        """Change the settings of the group"""
        if title is not None:
            self.title = title

        if REQUEST is not None:
            return self.manage_groupForm(manage_tabs_message='Settings changed')

    def manage_editRoles(self, role={}, REQUEST=None):
        """Change the role mappings of the group"""
        for user, roles in role.items():
            self.setMemberRoles(user, roles)

        for userid in self.getUsers():
            if userid not in role.keys():
                self.setMemberRoles(userid, [])

        if REQUEST is not None:
            return self.manage_groupForm(
                manage_tabs_message='Role mappings changed')

    def manage_addUser(self, userids, REQUEST=None):
        """Add a user to the members of the group"""
        # XXX check that user exists
        self.addUsers(userids)
        if REQUEST is not None:
            return self.manage_groupForm(manage_tabs_message='Users added')

    def manage_deleteUsers(self, selected, REQUEST=None):
        """Delete the users in the "selected" list of userids"""
        for userid in selected:
            if userid in self.getUsers():
                del self.members[userid]
        if REQUEST is not None:
            return self.manage_groupForm(manage_tabs_message='Users deleted')

    def addUsers(self, userids):
        for userid in userids:
            if not userid in self.members.keys():
                self.members[userid] = []


class GroupRolesPlugin(Folder):
    """This plugin stores the user definitions in the ZODB"""
    security = ClassSecurityInfo()
    __implements__ = (IGroupPlugin,IRolePlugin)

    meta_type = 'Group Roles Plugin'
    id = 'groups'
    title = 'Group Roles'
    plugin_id = 'groupRoles'

    manage_options = ({'label':'Groups', 'action':'manage_groupsForm'},) + \
                     SimpleItem.manage_options

    local_manage_methods = ({'id':'LocalGroups',
                             'label':'Local Groups',
                             'type': 'form',
                             'action':'manage_localGroupsForm'},
                             {'id':'ApplyGroups',
                             'label':'Apply Groups',
                             'type': 'method',
                             'action':'applyGroups'},
                             {'id':'UnapplyGroups',
                             'label':'Unapply Groups',
                             'type': 'method',
                             'action':'unapplyGroups'},
                             {'id':'SetGroups',
                             'label':'SetGroups',
                             'type': 'method',
                             'action':'setGroupsOnObject'},
                             {'id':'GetGroups',
                             'label':'GetGroups',
                             'type': 'method',
                             'action':'getGroupsOnObject'},
                           )
    #
    # ZMI methods for the GroupPlugin
    #

    manage_groupsForm = DTMLFile('zmi/groupRolesGroups', globals())
    manage_addGroupForm = DTMLFile('zmi/groupRolesAddGroup', globals())
    manage_localGroupsForm = DTMLFile('zmi/groupRolesLocalGroups', globals())

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

    def applyGroups(self, apply_groups=[], REQUEST=None):
        """Set which groups should be applied locally"""
        groups = self.manage_groupRolesGetGroups()
        for group in apply_groups:
            if group not in groups:
                groups.append(group)
        self.manage_groupRolesSetGroups(groups)
        if REQUEST is not None:
            return self.manage_groupRolesLocalGroups(
                manage_tabs_message='Groups Applied.')

    def unapplyGroups(self, unapply_groups=[], REQUEST=None):
        """Set which groups should be applied locally"""
        groups = self.manage_groupRolesGetGroups()
        for group in unapply_groups:
            if group in groups:
                groups.remove(group)
        self.manage_groupRolesSetGroups(groups)
        if REQUEST is not None:
            return self.manage_groupRolesLocalGroups(
                manage_tabs_message='Groups removed.')

    def getGroupsOnObject(self, object=None):
        if object is None:
            object = self
        return getattr(object, '_applied_groups', [])

    def setGroupsOnObject(self, groups):
        return setattr(self, '_applied_groups', groups)

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
    def addGroup(self, id, title):
        self._setObject(id,Group(id, title))

    def getGroupIds(self):
        return self.objectIds('Group')

    def getGroups(self):
        return self.objectItems('Group')

    def getGroup(self, id):
        return getattr(self, id, None)

    def getLocalRolesForUser(self, user, object):
        roles = []
        for group in self.getGroupsOnObject(object):
            groupob = self.getGroup(group)
            roles.extend(groupob.getMemberRoles(user))
        return roles

    def userHasLocalRole(self, user, object, role):
        for group in self.getGroupsOnObject(object):
            groupob = self.getGroup(group)
            if groupob.userHasRole(user, role):
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


def manage_addGroupRolesPlugin(self, REQUEST=None):
    """ """
    ob = GroupRolesPlugin()
    self = self.this()
    if hasattr(aq_base(self), ob.id):
        return MessageDialog(
            title='Item Exists',
            message='This object already contains an %s' % id.title,
            action='%s/manage_main' % REQUEST['URL1'])
    self._setObject(ob.id, ob)
    if REQUEST is not None:
        REQUEST['RESPONSE'].redirect(self.absolute_url() + '/manage_main')

