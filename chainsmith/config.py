"""
Use a Config object to manage commandline arguments,
environment variables and yaml config file.
"""
from argparse import ArgumentParser
from os import environ
from os.path import expanduser
import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


class Config(dict):
    """
    A Config class will read arguments, and yaml file
    and return a value if it is in either,
    or environment.
    """

    __args = None
    __yaml = None

    def __init__(self):
        super().__init__()
        self.get_arguments()
        self.read_configfile()
        self.read_environment()

    def get_arguments(self):
        """
        This function collects all config and initializes all objects.
        """
        parser = ArgumentParser(description="Tool to create an SSL chain with "
                                            "root CA, intermediates, and "
                                            "server/client certificates from "
                                            "yamlconfig.")
        config_path = environ.get('CHAINSMITH_CONFIG',
                                  '/etc/chainsmith/chainsmith.yml')
        parser.add_argument("-c", "--configfile",
                            default=expanduser(config_path),
                            help='The config file to use')
        parser.add_argument("--hosts",
                            help='Read servers from an ansible hosts file. '
                                 'Can also be set per intermediate in config '
                                 'yaml.')
        parser.add_argument("-C", "--certspath", default=None,
                            help='Write the yaml with certs to a file. '
                                 'Leave empty for stdout.')
        parser.add_argument("-p", "--privatekeyspath", default=None,
                            help='Write the yaml with keys to a file. '
                                 'Leave empty for stderr.')
        parser.add_argument("-t", "--tmpdir",
                            help='Tempdir for generating the certs. '
                                 'Leave empty for mktemp.')
        parser.add_argument("-d", "--debug", action='store_true',
                            help='Print openssl output to stdout and stderr. '
                                 'Print to files in tmpdir when not set.')
        self.__args = parser.parse_args()
        self.merge(vars(self.__args))

    def read_configfile(self):
        """
        This function reads and returns config data
        """
        # Configuration file look up.
        with open(self['configfile'], encoding="utf8") as configfile:
            self.__yaml = yaml.load(configfile, Loader=Loader)
        self.merge(self.__yaml)

    def read_environment(self):
        """
        This function reads config from environment vars
        """
        self.merge({k.lower()[11:]: v
                    for k, v in environ.items()
                    if k.startswith('CHAINSMITH_')})

    def merge(self, other):
        """
        merge the key/values of other dicts with key/values of self
        :param other: the other dict to merge in
        :return:
        """
        for key, value in other.items():
            self[key.lower()] = value
