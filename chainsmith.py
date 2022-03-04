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
import tempfile
import yaml

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


def readConfig():
    configFile = os.environ.get('CHAINSMITH_CONFIG', './config/chainsmith.yml')
    config = yaml.load(open(configFile), Loader=Loader)
    return config


def hostInfoFromInventory(hostsfile):
    try:
        groups = yaml.load(open(hostsfile).read())
    except Exception as e:
        raise Exception('could not open', hostsfile, e)
    hosts = []
    try:
        for _, groupinfo in groups['all']['children'].items():
            try:
                hosts += [ host for host in groupinfo['hosts']]
            except KeyError:
                continue
    except KeyError:
        raise Exception('missing all>children in '+hostsfile)
    if not hosts:
        raise Exception('no groups with hosts in all>children in '+hostsfile)
    return hosts


def main():
    config = readConfig()
    certs = {}
    pems = {}
    subject = TlsSubject(config.get('subject',
        "C=NL/postalCode=3721 MA, ST=Utrecht, L=Bilthoven/street=Antonie v Leeuwenhoekln 9, "
        "O=Rijksinstituut voor Volksgezondheid en Milieu (RIVM), OU=Postgres bouwblok, CN=postgres.rivm.nl"))
    tmpdir = config.get('tmpdir', os.environ.get('CHAINSMITH_TMPPATH', ''))
    if not tmpdir:
        tmpdir = tempfile.mkdtemp()
    root = TlsCA(os.path.join(tmpdir, 'tls'), subject.get('CN', 'postgres'), 'ca', None)
    root.set_subject(subject)
    root.create_ca_cert()
    for intermediate in config['intermediates']:
        if 'servers' in intermediate:
            intermediate_server = root.create_int(intermediate['name'], 'server')
            servers = intermediate['servers']
            hostsfile = intermediate.get('environment', os.environ.get('CHAINSMITH_ENV', ''))
            if hostsfile:
                for server in hostInfoFromInventory(hostsfile):
                    if server in servers:
                        continue
                    ip_address = socket.gethostbyname(server)
                    servers[server] = [ip_address]
            for name, alts in servers.items():
                srvr = [ name ] + alts
                intermediate_server.create_cert(srvr)
            certs[intermediate['name']] = intermediate_server.get_certs()
            pems[intermediate['name']] = intermediate_server.get_pems()
        elif 'clients' in intermediate:
            intermediate_client = root.create_int(intermediate['name'], 'client')
            for clnt in intermediate['clients']:
                intermediate_client.create_cert([clnt])
            certs[intermediate['name']] = intermediate_client.get_certs()
            pems[intermediate['name']] = intermediate_client.get_pems()
        else:
            raise Exception('intermediate of unknown type. Either specify "clients" or "servers"', intermediate)

    certspath =  config.get('certspath', os.environ.get('CHAINSMITH_CERTSPATH', 'certs.yml'))
    with open(certspath, 'w') as certsfile:
        certsfile.write('---\n')
        certsfile.write(yaml.dump({ 'certs': certs } , Dumper=Dumper, default_flow_style=False, default_style='|'))

    pemspath = config.get('pemspath', os.environ.get('CHAINSMITH_PEMSPATH', 'pems.yml'))
    with open(pemspath, 'w') as pemsfile:
        pemsfile.write('---\n')
        pemsfile.write(yaml.dump( { 'certs_keys': pems }, Dumper=Dumper, default_flow_style=False, default_style='|'))


if __name__ == "__main__":
    main()
