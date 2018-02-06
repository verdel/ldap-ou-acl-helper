#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ldap3 import Server, ServerPool, Connection, FIRST, AUTO_BIND_NO_TLS, SUBTREE
import argparse
from os import path
import sys
import asyncio
import signal

queue = asyncio.Queue()


def signal_handler(signal, frame):
    sys.exit(0)


def stdin_producer():
    data = sys.stdin.readline()
    asyncio.async(queue.put(data))


async def consumer(args, bindpasswd, conn):
    while True:
        try:
            input = await queue.get()
            if len(input) == 0:
                raise RuntimeError
            else:
                input = input.split()

        except Exception as exc:
            if isinstance(conn, Connection):
                if conn.bound:
                    conn.unbind()
            break
            sys.exit()

        try:
            id = input[0]
            username = input[1]
            ou = input[2]

            if args.strip_realm:
                username = username.split('@')[0]
            if args.strip_domain and '\\' in username:
                username = username.split('\\')[1]

            if isinstance(conn, Connection):
                if conn.closed:
                    conn = get_ldap_connection(server=args.server,
                                               port=args.port,
                                               ssl=args.ssl,
                                               timeout=int(args.timeout),
                                               binddn=args.binddn,
                                               bindpasswd=bindpasswd)

                if conn.bound:
                    try:
                        search_result = await get_ldap_info(connection=conn,
                                                            timelimit=int(args.timelimit),
                                                            binddn=args.binddn,
                                                            bindpasswd=bindpasswd,
                                                            ou=ou,
                                                            basedn=args.basedn,
                                                            filter=args.filter,
                                                            username=username)

                    except Exception as exc:
                        print('{} BH message={}({})'.format(id, type(exc).__name__, exc))
                        conn.strategy.close()
                        if conn.closed:
                            conn.bind()

                    else:
                        print('{} {}'.format(id, search_result))

            else:
                print('{} BH message="LDAP connection could not be established"'.format(id))
                break
                sys.exit()
            sys.stdout.flush()
        except:
            continue


def get_ldap_connection(server=[], port='', ssl=False, timeout=0, binddn='', bindpasswd=''):
    try:
        server_pool = ServerPool([Server(item, port, use_ssl=ssl, connect_timeout=3) for item in server],
                                 FIRST,
                                 active=3,
                                 exhaust=60)
        conn = Connection(server_pool,
                          auto_bind=AUTO_BIND_NO_TLS,
                          read_only=True,
                          receive_timeout=timeout,
                          check_names=True,
                          user=binddn, password=bindpasswd)
    except Exception as exc:
        print('ext_acl_ldap_group LDAP bind error {}({})'.format(type(exc).__name__, exc))
        return False
    else:
        return conn


async def get_ldap_info(connection='', timelimit=0, ou='', basedn='', filter='', username=''):
    if not connection:
        return 'BH message="LDAP connection could not be established"'

    try:
        connection.search(search_base=basedn.replace('%ou', ou),
                          search_filter=u'(&({}))'.format(filter.replace('%u', username)),
                          search_scope=SUBTREE,
                          attributes=['sAMAccountName'],
                          time_limit=timelimit,
                          get_operational_attributes=True)

    except Exception as exc:
        return 'BH message={}({})'.format(type(exc).__name__, exc)

    else:
        if len(connection.response) > 0:
            return u'OK tag="{}"'.format(ou)
        else:
            return 'ERR'


def create_cli():
    parser = argparse.ArgumentParser(description='Squid external acl ldap ou helper')
    parser.add_argument('-d', '--binddn', type=str, required=True,
                        help='DN to bind as to perform searches')
    parser.add_argument('-w', '--bindpasswd', type=str,
                        help='password for binddn')
    parser.add_argument('-W', '--secretfile',
                        help='read password for binddn from file secretfile')
    parser.add_argument('-s', '--server', action='append', required=True,
                        help='LDAP server. Can be set multiple instance. Use first active strategy')
    parser.add_argument('-p', '--port', type=int, default=389,
                        help='LDAP server port (defaults to %(default)i)')
    parser.add_argument('-z', '--ssl', action='store_true',
                        help='SSL encrypt the LDAP connection')
    parser.add_argument('-c', '--timeout', type=int, default=10,
                        help='connect timeout (defaults to %(default)i)')
    parser.add_argument('-t', '--timelimit', type=int, default=10,
                        help='search time limit (defaults to %(default)i)')
    parser.add_argument('-b', '--basedn', type=str, required=True,
                        help='base dn under where to search for users. %%ou = OU')
    parser.add_argument('-f', '--filter', type=str, required=True,
                        help='user search filter pattern. %%u = login')
    parser.add_argument('-k', '--strip-realm', action='store_true',
                        help='strip Kerberos realm from usernames')
    parser.add_argument('-n', '--strip-domain', action='store_true',
                        help='strip NT domain from usernames')
    return parser


def main():
    signal.signal(signal.SIGINT, signal_handler)
    parser = create_cli()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()
    conn = None

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
    sys.stdout.flush()
    if bindpasswd:
        try:
            conn = get_ldap_connection(server=args.server,
                                       port=args.port,
                                       ssl=args.ssl,
                                       timeout=int(args.timeout),
                                       binddn=args.binddn,
                                       bindpasswd=bindpasswd)
        except:
            pass
    else:
        sys.exit()

    loop = asyncio.get_event_loop()
    loop.add_reader(sys.stdin, stdin_producer)
    loop.run_until_complete(consumer(args, bindpasswd, conn))


if __name__ == '__main__':
    main()
