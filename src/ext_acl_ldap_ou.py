#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ldap3 import Server, Connection, AUTO_BIND_NO_TLS, SUBTREE
import argparse
from os import path
import sys


def get_ldap_info(server='', port='', tls=False, timeout=0, timelimit=0, binddn='', bindpasswd='', ou='', basedn='', filter='', username=''):
    try:
        with Connection(Server(server, port, use_ssl=tls),
                        auto_bind=AUTO_BIND_NO_TLS,
                        read_only=True,
                        receive_timeout=timeout,
                        check_names=True,
                        user=binddn, password=bindpasswd) as c:

            c.search(search_base=basedn.replace('%ou', ou),
                     search_filter='(&({}))'.format(filter.replace('%v', username)),
                     search_scope=SUBTREE,
                     attributes=['sAMAccountName'],
                     time_limit=timelimit,
                     get_operational_attributes=True)
    except Exception as exc:
        print('BH message={}({})'.format(type(exc).__name__, exc))
    else:
        if len(c.response) > 0:
            print('OK tag="{}"'.format(ou))
        else:
            print('ERR')


def main():
    parser = argparse.ArgumentParser(description='Squid external acl ldap ou helper')
    parser.add_argument('-d', '--binddn', type=str, required=True,
                        help='DN to bind as to perform searches')
    parser.add_argument('-w', '--bindpasswd', type=str,
                        help='password for binddn')
    parser.add_argument('-W', '--secretfile',
                        help='read password for binddn from file secretfile')
    parser.add_argument('-s', '--server', type=str, default='localhost',
                        help='LDAP server (defaults to %(default)s)')
    parser.add_argument('-p', '--port', type=int, default=389,
                        help='LDAP server port (defaults to %(default)i)')
    parser.add_argument('-z', '--tls', action='store_true',
                        help='TLS encrypt the LDAP connection')
    parser.add_argument('-c', '--timeout', type=int, default=10,
                        help='connect timeout (defaults to %(default)i)')
    parser.add_argument('-t', '--timelimit', type=int, default=10,
                        help='search time limit (defaults to %(default)i)')
    parser.add_argument('-b', '--basedn', type=str, required=True,
                        help='base dn under where to search for users')
    parser.add_argument('-f', '--filter', type=str, required=True,
                        help='base dn under where to search for users')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    if hasattr(args, 'bindpasswd') and args.bindpasswd:
        bindpasswd = args.bindpasswd
    elif hasattr(args, 'secretfile') and args.secretfile:
        if path.isfile(args.secretfile):
            try:
                with open(args.secretfile, 'r') as passwdfile:
                    bindpasswd = passwdfile.readline().replace('\n', '')
            except Exception as exc:
                print('ext_acl_ldap_ou Runtime error {}({})'.format(type(exc).__name__, exc))
                bindpasswd = ''
        else:
            print('ext_acl_ldap_ou Password file {} not found'.format(args.secretfile))
            bindpasswd = ''
    else:
        print('ext_acl_ldap_ou Password for binddn is not set')
        bindpasswd = ''

    while 1:
        try:
            input = sys.stdin.readline().split()
        except KeyboardInterrupt:
            sys.exit()
        try:
            username = input[0]
            ou = input[1]
            get_ldap_info(server=args.server,
                          port=args.port,
                          tls=args.tls,
                          timeout=int(args.timeout),
                          timelimit=int(args.timelimit),
                          binddn=args.binddn,
                          bindpasswd=bindpasswd,
                          ou=ou,
                          basedn=args.basedn,
                          filter=args.filter,
                          username=username)
            sys.stdout.flush()
        except:
            continue


if __name__ == '__main__':
    main()
