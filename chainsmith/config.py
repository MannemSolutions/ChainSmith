from argparse import ArgumentParser
from os import environ
from os.path import expanduser
import yaml

try:
    from yaml import CLoader as Loader
except ImportError:
    from yaml import Loader


class Config(dict):
    '''
    A Config class will read arguments, and yaml file and return a value if it is in either, or environment.
    '''

    __args = None
    __yaml = None

    def __init__(self):
        self.get_arguments()
        self.read_configfile()

    def get_arguments(self):
        '''
        This function collects all config and initializes all objects.
        '''
        parser = ArgumentParser(description="Tool to create an SSL chain with root CA, intermediates"
                                            ", and server/client certificates from yaml config.")
        config_path = environ.get('CHAINSMITH_CONFIG', './config/chainsmith.yml')
        parser.add_argument("-c", "--configfile", default=expanduser(config_path),
                            help='The config file to use')
        parser.add_argument("-o", "--output", default=None,
                            help='Write the yaml with certs to a file. Leave empty for stdout')
        parser.add_argument("-p", "--pem", default=None,
                            help='Write the yaml with private keys to a file. Leave empty for stderr')
        parser.add_argument("-t", "--tmpdir", 
                            help='The tempdir to use for generating the certs. Leave empty for mktemp')
        parser.add_argument("-d", "--debug", action='store_true',
                            help='Print openssl output to stdout and stderr. Print to files in tmpdir when not set.')
        self.__args = parser.parse_args()
        self.merge(vars(self.__args))

    def read_configfile(self):
        '''
        This function reads and returns config data
        '''
        # Configuration file look up.
        with open(self['configfile']) as configfile:
            self.__yaml = yaml.load(configfile, Loader=Loader)
        self.merge(self.__yaml)

    def merge(self, other):
        for key, value in other.items():
            self[key] = value