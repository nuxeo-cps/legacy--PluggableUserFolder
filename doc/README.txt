PluggableUserFolder: A Zope UserFolder with authentication plugins

  PluggableUserFolder is a Zope user folder that is designed to be
  extensible in all ways. It supports extending via "plugins"to add
  support both for ways of identifying the users, such as using
  cookies instead of Basic HTTP Authentication, and adding new
  sources of users, such as LDAP or SQL sources, and also extending
  the role management, such as group support and black lists.

  It also supports using all of these simultaneously. You can have users
  defined in Zope, in an SQL database and via LDAP, all at once. You can
  have groups and blacklists at the same time. You can support cookies
  and SSL Certificates without problems.

  Installation

    All you need is to expand the tgz file into a diretory and
    place it into the zope Products folder, and restart Zope.

    Please note that the Pluggable User Folder may conflict with other
    products that patch RoleManager. Typically it will clash with
    any products that provide group support or in any other way
    modify the role management.

  Bugs

    You are currently able to delete all identification plugins, inclusing
    BasicIdentification. If you do this on a root acl_users, you are in big
    trouble, since you  will not be able to log in, period. Not even the
    Emergency User will work. This will need to be adressed, somehow.

      - Not being able to delete the last identification plugin!

      - Automatically adding the BasicIdentification if no other
        autentification plugins exist on startup?

      - Having a magic file, like access and inituser either in the root
        or in the PluggableUserFolder dir that when it exists, makes some
        kind of 'restore', ie adds BasicIdentification. That file +
        access would then reenable the emergency user.

      - Automatically add BasicIdentification if access exists?

      - Make a built-in, always existing 'EmergencyIdentification' plugin,
        or somehow otherwise always allow Basic identification together with
        the emergency user?

  More information

    There is now a "cps-devel Mailing
    list":http://lists.nuxeo.com/mailman/listinfo/cps-devel for CPS3 (and CPS2)
    developers, as well for other products developped by Nuxeo. 
    
    CPS users lists ("cps-users
    (english)":http://lists.nuxeo.com/mailman/listinfo/cps-users and
    "cps-users-fr
    (french)":ttp://lists.nuxeo.com/mailman/listinfo/cps-users-fr) are also
    available.
