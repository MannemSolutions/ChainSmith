#!/usr/bin/python

"""
Implementation as described here:
https://www.golinuxcloud.com/generate-self-signed-certificate-openssl/#Create_encrypted_password_file_Optional
https://www.golinuxcloud.com/openssl-create-certificate-chain-linux/
https://www.golinuxcloud.com/openssl-create-client-server-certificate/
"""

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

DEFAULT_SUBJECT = {"C": "NL",
                   "ST": "Somestate",
                   "L": "Somecity",
                   "O": "Mannem Solutions",
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
        with open(hosts_path, encoding="utf8") as hosts_file:
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
        raise Exception('missing all>children in ' + hosts_path) from key_error
    if not hosts:
        raise Exception('no groups with hosts in all>children in '+hosts_path)
    return hosts


def add_intermediate(root, intermediate, config, data):
    """
    Create an intermediate, and read back certs
    """
    name = intermediate['name']
    if 'clientservers' in intermediate:
        clientserver = root.create_int(name, 'clientserver')
        for host in hosts_from_inventory(
                intermediate.get('hosts', config.get('hosts'))):
            if host in intermediate['clientservers']:
                continue
            intermediate['clientservers'][host] = [gethostbyname(host)]
        for clientserver_name, alts in intermediate['clientservers'].items():
            clientserver.create_cert([clientserver_name] + alts)
        data['certs'][name] = clientserver.get_certs()
        data['private_keys'][name] = clientserver.get_private_keys()
    elif 'servers' in intermediate:
        server = root.create_int(name, 'server')
        for host in hosts_from_inventory(
                intermediate.get('hosts', config.get('hosts'))):
            if host in intermediate['servers']:
                continue
            intermediate['servers'][host] = [gethostbyname(host)]
        for server_name, alts in intermediate['servers'].items():
            server.create_cert([server_name] + alts)
        data['certs'][name] = server.get_certs()
        data['private_keys'][name] = server.get_private_keys()
    elif 'clients' in intermediate:
        intermediate_client = root.create_int(name, 'client')
        for client in intermediate['clients']:
            intermediate_client.create_cert([client])
        data['certs'][name] = intermediate_client.get_certs()
        data['private_keys'][name] = intermediate_client.get_private_keys()
    else:
        raise Exception('intermediate of unknown type. '
                        'Either specify "clients" or "servers"',
                        intermediate)


def write_data(config, data):
    """
    Write yaml data to stdout, and stderr or files.
    """
    for key, datum in data.items():
        yaml_data = yaml.dump({key: datum}, Dumper=Dumper,
                              default_flow_style=False,
                              default_style='|')
        path = config.get(key.replace('_', '') + 'path')
        if path:
            with open(path, 'w', encoding="utf8") as file:
                file.write('---\n')
                file.write(yaml_data)
        else:
            if 'private' in key:
                redirect = stderr
            else:
                redirect = stdout
            redirect.write(yaml_data)


def from_yaml():
    """
    Reads the config and creates the chain
    :return:
    """
    config = Config()
    data = {'certs': {}, 'private_keys': {}}
    subject = TlsSubject(config.get('subject', DEFAULT_SUBJECT))
    tmpdir = config.get('tmpdir', None)
    if not tmpdir:
        tmpdir = tempfile.mkdtemp()
        print(f"# More info in in {tmpdir}.")
    root = TlsCA(join(tmpdir, 'tls'), subject.get('CN', 'postgres'),
                 'ca', None)
    with open(join(tmpdir, 'stdout.log'), 'w', encoding="utf8") as outlog, \
            open(join(tmpdir, 'stderr.log'), 'w', encoding="utf8") as errlog:
        if not config.get('debug'):
            root.set_debug_output(outlog, errlog)
        root.set_subject(subject)
        root.create_ca_cert()
        for intermediate in config['intermediates']:
            add_intermediate(root, intermediate, config, data)
        write_data(config, data)
