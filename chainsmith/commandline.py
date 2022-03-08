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
from sys import stdout, stderr
import tempfile
import yaml
from chainsmith.tls import TlsCA, TlsSubject
from chainsmith.config import Config

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper


DEFAULT_SUBJECT = {"C":  "NL/postalCode=2403 VP",
     "ST": "Zuid Holland",
     "L":  "Alphen aan den Rijn/"
           "street=Weegbreestraat 7",
     "O":  "Mannem Solutions",
     "OU": "Chainsmith TLS chain maker",
     "CN": "chainsmith"
}

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


def from_yaml():
    """
    Reads the config and creates the chain
    :return:
    """
    config = Config()
    certs = {}
    pems = {}
    subject = TlsSubject(config.get('subject', DEFAULT_SUBJECT))
    tmpdir = config.get('tmpdir', None)
    if not tmpdir:
        tmpdir = tempfile.mkdtemp()
    root = TlsCA(join(tmpdir, 'tls'), subject.get('CN', 'postgres'),
                 'ca', None)
    if not config.get('debug'):
        root.set_debug_output(open(join(tmpdir, 'stdout.log'), 'w'),
                              open(join(tmpdir, 'stderr.log'), 'w'))
    root.set_subject(subject)
    root.create_ca_cert()
    for intermediate in config['intermediates']:
        if 'servers' in intermediate:
            intermediate_server = root.create_int(intermediate['name'],
                                                  'server')
            for server in hosts_from_inventory(
                    intermediate.get('environment',
                                     config.get('CHAINSMITH_ENV', ''))):
                if server in intermediate['servers']:
                    continue
                intermediate['servers'][server] = [gethostbyname(server)]
            for name, alts in intermediate['servers'].items():
                intermediate_server.create_cert([name] + alts)
            certs[intermediate['name']] = intermediate_server.get_certs()
            pems[intermediate['name']] = intermediate_server.get_private_keys()
        elif 'clients' in intermediate:
            intermediate_client = root.create_int(intermediate['name'],
                                                  'client')
            for client in intermediate['clients']:
                intermediate_client.create_cert([client])
            certs[intermediate['name']] = intermediate_client.get_certs()
            pems[intermediate['name']] = intermediate_client.get_private_keys()
        else:
            raise Exception('intermediate of unknown type. '
                            'Either specify "clients" or "servers"',
                            intermediate)
    for path, data, redirect in [
        ('certspath', {'certs': certs}, stdout),
        ('pemspath', {'private_keys': pems}, stderr)]:
        yaml_data = yaml.dump(data, Dumper=Dumper,
                              default_flow_style=False,
                              default_style='|')
        path = config.get(path)
        if path:
            print(path)
            with open(path, 'w') as file:
                file.write('---\n')
                file.write(yaml_data)
        else:
            redirect.write(yaml_data)
