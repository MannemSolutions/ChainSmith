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

DEFAULT_SUBJECT = {
    "C": "NL",
    "ST": "Somestate",
    "L": "Somecity",
    "O": "Mannem Solutions",
    "OU": "Chainsmith TLS chain maker",
    "CN": "chainsmith",
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


def add_intermediate(root, intermediate_config, data):
    """
    Create an intermediate, and read back certs
    """
    intermediate_name = intermediate_config['name']
    intermediate_ca = root.create_int(intermediate_name,
                                      intermediate_config)
    try:
        for client in intermediate_config['clients']:
            intermediate_ca.create_cert([client])
    except KeyError:
        pass

    if 'serverAuth' in intermediate_config.get('extended_key_usages', []):
        for host in hosts_from_inventory(intermediate_config.get('hosts')):
            if host in intermediate_config['servers']:
                continue
            intermediate_config['servers'][host] = [gethostbyname(host)]

    try:
        for server_name, alts in intermediate_config['servers'].items():
            intermediate_ca.create_cert([server_name] + alts)
    except KeyError:
        pass

    data['certs'][intermediate_name] = intermediate_ca.get_certs()
    data['private_keys'][intermediate_name] = \
        intermediate_ca.get_private_keys()


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
                 {}, None)
    with open(join(tmpdir, 'stdout.log'), 'w', encoding="utf8") as outlog, \
            open(join(tmpdir, 'stderr.log'), 'w', encoding="utf8") as errlog:
        if not config.get('debug'):
            root.set_debug_output(outlog, errlog)
        root.set_subject(subject)
        root.create_ca_cert()
        for intermediate in config['intermediates']:
            intermediate['hosts'] = intermediate.get('hosts',
                                                     config.get('hosts'))
            add_intermediate(root, intermediate, data)
        write_data(config, data)
