#!/usr/bin/python

"""
Implementation as described here:
https://www.golinuxcloud.com/generate-self-signed-certificate-openssl/#Create_encrypted_password_file_Optional
https://www.golinuxcloud.com/openssl-create-certificate-chain-linux/
https://www.golinuxcloud.com/openssl-create-client-server-certificate/
"""

from os import environ
from os.path import join
from socket import gethostbyname
import tempfile
import yaml
from lib.tls import TlsCA, TlsSubject

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


def read_config():
    """
    Read config from yaml file
    """
    config_path = environ.get('CHAINSMITH_CONFIG', './config/chainsmith.yml')
    with open(config_path) as config_file:
        return yaml.load(config_file, Loader=Loader)


def hosts_from_inventory(hosts_path):
    """
    Read host info from Ansible inventory hosts file
    :param hosts_path: The file to read hostnames from
    :return: a list of hosts as found in the Ansible inventory hosts file
    """
    if not hosts_path:
        return []
    try:
        with open(hosts_path) as hosts_file:
            groups = yaml.load(hosts_file.read(), Loader=Loader)
    except Exception as error:
        raise Exception('could not open', hosts_path) from error
    hosts = []
    try:
        for _, group_info in groups['all']['children'].items():
            try:
                hosts += group_info['hosts']
            except KeyError:
                continue
    except KeyError as key_error:
        raise Exception('missing all>children in '+hosts_path) from key_error
    if not hosts:
        raise Exception('no groups with hosts in all>children in '+hosts_path)
    return hosts


def main():
    """
    Reads the config and creates the chain
    :return:
    """
    config = read_config()
    certs = {}
    pems = {}
    subject = TlsSubject(config.get('subject',
                                    {"C":  "NL/postalCode=2403 VP",
                                     "ST": "Zuid Holland",
                                     "L":  "Alphen aan den Rijn/"
                                           "street=Weegbreestraat 7",
                                     "O":  "Mannem Solutions",
                                     "OU": "Chainsmith TLS chain maker",
                                     "CN": "chainsmith"}
                                    ))
    tmpdir = config.get('tmpdir', environ.get('CHAINSMITH_TMPPATH', ''))
    if not tmpdir:
        tmpdir = tempfile.mkdtemp()
    root = TlsCA(join(tmpdir, 'tls'), subject.get('CN', 'postgres'),
                 'ca', None)
    root.set_subject(subject)
    root.create_ca_cert()
    for intermediate in config['intermediates']:
        if 'servers' in intermediate:
            intermediate_server = root.create_int(intermediate['name'],
                                                  'server')
            for server in hosts_from_inventory(
                    intermediate.get('environment',
                                     environ.get('CHAINSMITH_ENV', ''))):
                if server in intermediate['servers']:
                    continue
                intermediate['servers'][server] = [gethostbyname(server)]
            for name, alts in intermediate['servers'].items():
                intermediate_server.create_cert([name] + alts)
            certs[intermediate['name']] = intermediate_server.get_certs()
            pems[intermediate['name']] = intermediate_server.get_pems()
        elif 'clients' in intermediate:
            intermediate_client = root.create_int(intermediate['name'],
                                                  'client')
            for client in intermediate['clients']:
                intermediate_client.create_cert([client])
            certs[intermediate['name']] = intermediate_client.get_certs()
            pems[intermediate['name']] = intermediate_client.get_pems()
        else:
            raise Exception('intermediate of unknown type. '
                            'Either specify "clients" or "servers"',
                            intermediate)

    with open(config.get('certspath',
                         environ.get('CHAINSMITH_CERTSPATH',
                                     'certs.yml')), 'w') as certs_file:
        certs_file.write('---\n')
        certs_file.write(yaml.dump({'certs': certs}, Dumper=Dumper,
                                   default_flow_style=False,
                                   default_style='|'))

    with open(config.get('pemspath',
                         environ.get('CHAINSMITH_PEMSPATH', 'pems.yml')),
              'w') as pems_file:
        pems_file.write('---\n')
        pems_file.write(yaml.dump({'certs_keys': pems}, Dumper=Dumper,
                                  default_flow_style=False,
                                  default_style='|'))


if __name__ == "__main__":
    main()
