PluggableUserFolder: A Zope UserFolder with authentication plugins

  AccessControl consists of several separate steps.

   * Identification: The way the client tells the server who the
     user is. When it comes to web, this is typically methods like
     Basic HTTP Authentication, Cookies or SSL Certificates.

   * Authentication: Making sure the user is who he/she is. This typically
     involves looking up the user in a user database and validating the users
     password.

   * Authorization: Making sure the authenticated user is authorized to do
     what the user is trying to do.

  In Zope these three steps are together known as Validation.

  Zope only supports one way of Authenticating users, namely mathching them
  against an internal user database. Being able to use external user
  databases is one of the most common requirements, and this has been
  accomodated by several different third-party user folders, who instead
  of storing the user data in the ZODB, make external calls to external user
  directories such as LDAP servers, Microsoft NT servers, or lookups in an
  SQL database. This works well, until you want to have several different
  sources of users. It also has the drawback that adding new features and
  extentions like Groups, or new high-level interfaces, only works with the
  default user folder, and not to the external user folders.

  The PluggableUserFolder is an attempt to fix these problems, by having a
  user folder that uses plugins for Authentication. This makes it possible
  to have several plugins to use several sources of users (typically both
  an LDAP source and an ZODB source). It also simplifies the implementation
  of new sources by letting you only implement the basic methods to get data
  from a data source, instead of implementing a complete user folder. Any
  features added to the user folder can then also directly be enjoyed by
  anybody using an external data source.

  Future development

    Zope out of the box also supports only Basic HTTP Authentication. CMF adds
    identification through Cookies with the CookieCrumbler product. It's using
    a rather ugly, but well-working method of faking a Basic HTTP
    Authentication header in the REQUEST object. It's possible to add new
    Identification methods in a similar way, if needed. However, the
    BasicUserFolder of Zope has an interface to let UserFolders handle
    identifications without this kind of REQUEST header, and it would therefore
    be possible to as a later stage add plugins for identification as well,
    thereby letting site administrators mix several types of identification
    schemes as needed, in an easy and predictable way.

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
