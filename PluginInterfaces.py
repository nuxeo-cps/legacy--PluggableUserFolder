# (c) 2003 Nuxeo SARL <http://nuxeo.com>
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

__doc__ = '''User Folder Plugin Interfaces'''
__version__ = '$Revision$'[11:-2]

import Interface

class IAuthenticationPlugin(Interface.Base):

    def isReadOnly(self):
        """Return 1 if you can not add, change or delete users"""

    def getUserNames(self):
        """Return a list of usernames"""

    def getUsers(self):
        """Return a list of user objects"""

    def getUser(self, name, password=None):
        """Return the named user object or None

        password should be passed when the user is retrieved for
        validation, since some authentication sources can't
        return the password, only authenticate it. By passing the
        password when retrieveing the user information, sources like
        LDAP only need one call for both passing and authenticating
        the user. Passing the password is therefore typically only
        done from within UserFolder.authenticate()."""

    def _doAddUser(self, name, password, roles, domains, **kw):
        """Create a new user
        
        This should be implemented by subclasses to do the actual adding of a
        user. The 'password' will be the original input password, unencrypted.
        The implementation of this method is responsible for performing any
        needed encryption."""

    def _doChangeUser(self, name, password, roles, domains, **kw):
        """Modify an existing user
        
        This should be implemented by subclasses to make the actual changes to
        a user. The 'password' will be the original input password,
        unencrypted. The implementation of this method is responsible for
        performing any needed encryption."""

    def _doDelUsers(self, names):
        """Delete one or more users
        
        This should be implemented by subclasses to do the actual deleting of
        users."""

class IIdentificationPlugin(Interface.Base):

    # Notes:
    # Todays Zope Userfolder assumes that the authentication information
    # is located in one string. This is because it is assumed to come
    # via the Authentication HTTP-header. Instead it often comes from
    # other places, such as cookies, or CGI environment variables.
    # The identify() method in a Zope userfolder therefore only takes one
    # parameter, the 'auth' authentification string.
    # Because of this, pluggable identification is done in two steps:
    # Step one creates an authentication string from the request and
    # auth parameters to validate(). These are then passed on to
    # BasicUserFolder.validate() that then calls identify()
    # which again uses the plugins this time to get a username and
    # password out of the authentication strings.
    #
    # This is a bit ugly, but the alternative is to completely override
    # BasicUserFolder.validate() and I don't want to do that right now, since
    # that would mean that the code would be exactly duplicated except the
    # call to identify().
    # A future version of this interface my instead have only one method:
    # def identify(self, auth, request):

    def makeAuthenticationString(self, request, auth):
        """Return an authentication string

        This string starts with the authentication type and then a space.
        The rest of the string contains the authentication data. Ex:
        'Basic bGVubmFydDpsZW5uYXJ0'
        'Apache-SSL skldjfhclkj4hrq3kj4hfqlbcqw874by'

        Returns None if identification could not be made.
        """

    def canIdentify(self, auth):
        """Return true if the plugin knows how to identify this string"""

    def identify(self, auth):
        """Return a username and a password from the authentication string"""


class IRolePlugin(Interface.Base):

    # These plugins change the assignment of roles to a user.
    # They do that by getting a user, a list of roles and a
    # context is the case of local roles, and modify that list
    # of roles. The list is then sent to the next plugin. This
    # way you can have several plugins that modify roles
    # independently of each other.

    def modifyGlobalRoles(self, user, roles):
        """Return a updated list of roles"""

    def modifyLocalRoles(self, user, object, roles):
        """Modify a list of local roles

        This is  XXX
        """

    def isUserAllowed(self, user, object, object_roles, previous):
        """Check local roles for just one role

        This method is called from User.allowed(), and allows for several
        shortcuts for the plugin. Firstly, it only cares about one role,
        the 'object_roles' role (called this because that's what
        User.allowed() calles it) so a plugin can "bail out" without having
        to traverse to the root if the status of a role is determined.
        Secondly, the "previous" parameter will send in the returned value
        from the previous plugin. A plugin that never blocks roles can
        therefore simply return 1 immediately if previous is set to one,
        and a plugin that never adds roles can return 0 immediately if
        previous is 0, in both cases needing no traversal at all.
        """

class IGroupPlugin(IRolePlugin):
    # XXX: I'm not sure if there are side effects of subclassinng
    # Interfaces...

    # This is a special type of IRolePlugin, to implement group support.
    # It extends the role modification with an API to support groups.
    # The API supports mainly the listing of groups, and also methods
    # that allow CMF to display basic local role management interfaces
    # for these groups.
    #
    # Group objects must in turn implement the IGroupObject interface.

    def getGroupIds(self):
        """Returns a list of the names of defined groups"""

    def getGroupFromId(self, id):
        """Returns the group object"""

        
class IGroupObject(Interface.Base):

    def getMembers(self):
        """Returns the names of the members of the group"""

    def manageForm(self):
        """Returns HTML code for a management form

        This form should be made to be displayed inside a CMF template,
        called on a RoleManager object.
        """