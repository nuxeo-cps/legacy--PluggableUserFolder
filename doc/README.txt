==================================================================
PluggableUserFolder: A Zope UserFolder with authentication plugins
==================================================================

:Revision: $Id$

.. sectnum::    :depth: 4
.. contents::   :depth: 4


PluggableUserFolder
===================

PluggableUserFolder is a Zope user folder that is designed to be
extensible in all ways. It supports extending via "plugins"to add
support both for ways of identifying the users, such as using
cookies instead of Basic HTTP Authentication, and adding new
sources of users, such as LDAP or SQL sources, and also extending
the role management, such as group support and black lists.

It also supports using all of these simultaneously. You can have
users defined in Zope, in an SQL database and via LDAP, all at
once. You can have groups and blacklists at the same time. You can
support cookies and SSL Certificates without problems.


Installation
============

All you need is to expand the gzipped tar file into a directory and place
it into the Zope Products folder, and restart Zope.

Please note that the Pluggable User Folder may conflict with other
products that patch RoleManager. Typically it will clash with any
products that provide group support or in any other way modify the
role management.


Bugs
====

You are currently able to delete all identification plugins,
including BasicIdentification. If you do this on a root acl_users,
you are in big trouble, since you will not be able to log in,
period. Not even the Emergency User will work. This will need to
be addressed, somehow.

- Not being able to delete the last identification plugin!

- Automatically adding the BasicIdentification if no other
  authentication plugins exist on startup?

- Having a magic file, like access and inituser either in the root
  or in the PluggableUserFolder directory that when it exists, makes
  some kind of 'restore', i.e. adds BasicIdentification. That file +
  access would then re-enable the emergency user.

- Automatically add BasicIdentification if access exists?

- Make a built-in, always existing 'EmergencyIdentification'
  plugin, or somehow otherwise always allow Basic identification
  together with the emergency user?

More information

There is now a "cps-devel mailing list" at:
http://lists.nuxeo.com/mailman/listinfo/cps-devel for CPS3 (and
CPS2) developers, as well as for other products developed by
Nuxeo. 

There are also CPS users lists:

- "cps-users (English)" at:
  http://lists.nuxeo.com/mailman/listinfo/cps-users

- "cps-users-fr (French)" at:
  http://lists.nuxeo.com/mailman/listinfo/cps-users-fr)


.. Emacs
.. Local Variables:
.. mode: rst
.. End:
.. Vim
.. vim: set filetype=rst:

