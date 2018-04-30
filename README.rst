==========================================================================
ldap-ou-acl-helper - Squid external acl ldap ou helper
==========================================================================


What is this?
*************
``ldap-ou-acl-helper`` provides an executable called ``ext_acl_ldap_ou``
for concurrent squid behavior.


Installation
************
*on most UNIX-like systems, you'll probably need to run the following
`install` commands as root or by using sudo*

**from source**

::

  pip install git+http://github.com/verdel/ldap-ou-acl-helper

**or**

::

  git clone git://github.com/verdel/ldap-ou-acl-helper.git
  cd ldap-ou-acl-helper
  python setup.py install

as a result, the ``ext_acl_ldap_ou`` executable will be installed into
a system ``bin`` directory

Usage
-----
::

    ext_acl_ldap_ou --help
    usage: ext_acl_ldap_ou.py [-h] -d BINDDN [-w BINDPASSWD] [-W SECRETFILE] -s
                          SERVER [-p PORT] [-z] [-c TIMEOUT] [-t TIMELIMIT] -b
                          BASEDN -f FILTER [-k] [-n]

    Squid external acl ldap ou helper

    optional arguments:
    -h, --help            show this help message and exit
    -d BINDDN, --binddn BINDDN
                        DN to bind as to perform searches
    -w BINDPASSWD, --bindpasswd BINDPASSWD
                        password for binddn
    -W SECRETFILE, --secretfile SECRETFILE
                        read password for binddn from file secretfile
    -s SERVER, --server SERVER
                        LDAP server. Can be set multiple instance. Use first
                        active strategy
    -p PORT, --port PORT  LDAP server port (defaults to 389)
    -z, --ssl             SSL encrypt the LDAP connection
    -c TIMEOUT, --timeout TIMEOUT
                        connect timeout (defaults to 10)
    -t TIMELIMIT, --timelimit TIMELIMIT
                        search time limit (defaults to 10)
    -b BASEDN, --basedn BASEDN
                        base dn under where to search for users. %ou = OU
    -f FILTER, --filter FILTER
                        user search filter pattern. %u = login
    -k, --strip-realm     strip Kerberos realm from usernames
    -n, --strip-domain    strip NT domain from usernames
