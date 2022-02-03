#!/usr/bin/python

"""
Implementation as described here:
https://www.golinuxcloud.com/generate-self-signed-certificate-openssl/#Create_encrypted_password_file_Optional
https://www.golinuxcloud.com/openssl-create-certificate-chain-linux/
https://www.golinuxcloud.com/openssl-create-client-server-certificate/
"""

from os import getcwd
from os.path import join
from lib.tls import TlsCA, TlsSubject 

def main():
    subject = TlsSubject("/C=NL/ST=Zuid Holland/L=Alphen aan den Rijn/O=Mannem Solutions/OU=IT/CN=postgres")
    servers = [
        ["server1", "192.168.1.11"],
        ["server2", "192.168.1.12"],
        ["server3", "192.168.1.13"],
    ]
    root = TlsCA(join(getcwd(), 'tls'), 'postgres', 'ca', None)
    root.set_subject(subject)
    root.create_ca_cert()
    intermediate_server = root.create_int('server', 'server')
    for s in servers:
        intermediate_server.create_cert(s[0], s[1:])

    clients = ["postgres", "wal-g", "patroni", "application"]
    intermediate_client = root.create_int('client', 'client')
    for c in clients:
        intermediate_client.create_cert(c, [])


if __name__ == "__main__":
    main()
