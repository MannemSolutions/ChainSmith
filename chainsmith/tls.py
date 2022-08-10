"""
This module handles Tls objects, which could be
- a TLS root ca or TLS intermediate (and private keys)
- a certificate (and private keys)
"""
from ipaddress import ip_address
from os import makedirs
from os.path import join, realpath, expanduser, exists
from string import digits, ascii_uppercase
from sys import stdout, stderr
from random import choice
from tempfile import NamedTemporaryFile
from subprocess import run

from chainsmith.exceptions import TlsPwdAlreadySetException
from chainsmith.config_file import ConfigFile, ConfigLine, ConfigChapter


def get_config_path():
    """
    Small helper to get the correct openssl.conf file regardless of
    distribution.
    """
    known_paths = [
        # MacOS, order before /etc/ssl/openssl.cnf, because that also
        # exists and is not the correct one to use as a default
        '/usr/local/etc/openssl@1.1/openssl.cnf',
        # RHEL
        '/etc/pki/tls/openssl.cnf',
        # Debian
        '/etc/ssl/openssl.cnf',
    ]
    for path in known_paths:
        if exists(path):
            return path
    raise Exception('Cannot find openssl.cnf on this distribution')


class TlsSubject(dict):
    """
    TlsSubject is a small helper class to wrap, unwrap and merge tls subjects
    with a form of:
       "/C=US/ST=Utah/L=Lehi/O=Your Company, Inc./OU=IT/CN=yourdomain.com"
    """

    def __init__(self, subject):
        super().__init__()
        if isinstance(subject, str):
            for pair in subject.split('/'):
                if '=' in pair:
                    key, value = pair.split('=', 2)
                    self[key] = value
        else:
            for key, value in subject.items():
                self[key] = value

    def string(self):
        """Return a string representation of a certificates subject"""
        return '/' + '/'.join([f'{k}={v}' for k, v in self.items()])

    def merge(self, other):
        """Merge a TlsSubject with another TlsSubject or a dict"""
        for key, value in other.items():
            self[key] = value

    def clone(self):
        """Return a clone of the subject"""
        clone = TlsSubject('')
        for key, value in self.items():
            clone[key] = value
        return clone

    def chapter(self):
        """
        Return a ConfigChapter that could represent
        the TlsSubject in a openssl.cnf file
        """
        chapter = ConfigChapter('req_distinguished_name')
        for key, value in self.items():
            chapter.append(ConfigLine(f'{key} = {value}'))
        chapter.append(ConfigLine(''))
        return chapter


# pylint: disable=too-many-public-methods
class TlsCA(dict):
    """
    TlsCA represents a certificate authority, either root or intermediate.
    It just is a placeholder for the folder, directories, config files, etc.
    And it has methods to create all, sign sub certificates, generate
    private keys, etc. if __parent is None, it is a root certificate, if not,
    it is a intermediate certificate. The class can be used to setup a
    CA store, and use it to sign requests for lower certificates.
    """

    # pylint: disable=too-many-instance-attributes
    __capath = ''
    __name = ''
    __cert_type = ''
    __config_file = ''
    __pem_file = ''
    __password_file = ''
    __cert_file = ''
    __chain_file = ''
    __subject = None
    __parent = None
    __stdout = stdout
    __stderr = stderr

    def __init__(self, capath, name, cert_type, parent):
        super().__init__()
        self.__capath = capath
        self.__name = name
        self.__cert_type = cert_type
        self.__config_file = join(capath, 'config', 'ca.cnf')
        self.__pem_file = join(capath, 'private', 'cakey.pem')
        self.__password_file = join(capath, 'private', 'capass.enc')
        self.__cert_file = join(capath, 'certs', 'cacert.pem')
        self.__chain_file = join(capath, 'certs', 'ca-chain-bundle.cert.pem')
        try:
            if parent is not None:
                self.set_subject(parent.subject())
                self.__parent = parent
            for folder in ['.', 'config', 'certs', 'csr',
                           'newcerts', 'private']:
                path = realpath(expanduser(join(capath, folder)))
                if not exists(path):
                    makedirs(path)
            serial_file = join(capath, 'serial')
            if not exists(serial_file):
                with open(serial_file, 'w', encoding="utf8") as serial:
                    serial.write('01')
            index_file = join(capath, 'index.txt')
            if not exists(index_file):
                with open(index_file, 'w', encoding="utf8"):
                    pass
        except OSError as os_err:
            print("Cannot open file:", os_err)

    def name(self):
        """Return the name of this TlsXA"""
        return self.__name

    def set_subject(self, subject):
        """Set a subject for this CA"""
        self.__subject = subject.clone()
        self.__subject['CN'] = self.name()

    def set_debug_output(self, out, err):
        """Set the stdout and stderr to log to"""
        self.__stdout = out
        self.__stderr = err

    def log_command(self, command):
        """log a command that is about to be run"""
        self.__stdout.write(command+':\n')
        self.__stdout.write('='*len(command)+'=\n')

    def log(self, line):
        """Log a line"""
        self.__stdout.write(line+'\n')

    def gen_pem_password(self, password=None):
        """Generate a random pem password"""
        if exists(self.__password_file):
            raise TlsPwdAlreadySetException(self.__password_file,
                                            "already exists, not replacing")
        if not password:
            password = ''.join(choice(ascii_uppercase + digits)
                               for _ in range(18))
            self.log(f'using a random password for {self.name()} '
                     f'pem: {password}')
        # This creates a tempfile, writes the password to it, creates the
        # enc file and removes the tempfile as atomic as possible
        try:
            with NamedTemporaryFile(mode='w') as tmp_file:
                tmp_file.write(password)
                tmp_file.flush()
                self.log("Running openssl genrsa for "+self.name())
                args = ['openssl', 'enc', '-aes256', '-salt', '-in',
                        tmp_file.name, '-out', self.__password_file, '-pass',
                        'file:'+tmp_file.name]
                self.log_command(' '.join(args))
                run(args, check=True, stdout=self.__stdout,
                    stderr=self.__stderr)
        except OSError as os_err:
            print("Cannot open file:", os_err)

    def subject(self):
        """Return the subject of this TlsCA"""
        return self.__subject.clone()

    def path(self):
        """
        Return the path where all config files, certs,
        private keys, etc. are stored
        """
        return self.__capath

    def configfile(self):
        """Return the path to the configfile"""
        return self.__config_file

    def gen_ca_cnf(self):
        """Generate a ca.cnf from openssl.cnf with many changes"""
        if self.__parent is not None:
            config_file = ConfigFile(self.__parent.configfile())
            config_file.set_key('CA_default', 'policy', 'policy_anything')
            # req_attributes contains _min and _max values that help with
            # prompt=yes, but not with prompt=no, so we are resetting to
            # empty chapter
            config_file.set_chapter(ConfigChapter('req_attributes'))
        else:
            config_file = ConfigFile(get_config_path())
            config_file.set_key('req', 'prompt', 'no')
            # config_file.set_key('', 'HOME', '.')
            # config_file.set_key('', 'RANDFILE', '$ENV::HOME/.rnd')
            # config_file.set_key('', 'oid_section', 'new_oids')
            if exists('/etc/crypto-policies/back-ends/opensslcnf.config'):
                # seems to have something to do with FIPS mode on RH8.
                # For more info see
                # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening
                config_file.set_key('', 'openssl_conf', 'default_modules')
                config_file.set_key('default_modules', 'ssl_conf',
                                    'ssl_module')
                config_file.set_key('ssl_module', 'system_default',
                                    'crypto_policy')
                config_file.set_key('crypto_policy',
                                    '.include /etc/crypto-policies/back-ends'
                                    '/opensslcnf.config', '')

            # config_file.set_key('CA_default', 'policy', 'policy_match')

            config_file.set_key('req', 'default_bits', '4096')

            chapter = ConfigChapter('v3_intermediate_ca')
            chapter.append(ConfigLine('subjectKeyIdentifier = hash'))
            chapter.append(ConfigLine('authorityKeyIdentifier = '
                                      'keyid:always,issuer'))
            chapter.append(ConfigLine('basicConstraints = critical, CA:true, '
                                      'pathlen:0'))
            chapter.append(ConfigLine('keyUsage = critical, digitalSignature, '
                                      'cRLSign, keyCertSign'))
            chapter.append(ConfigLine(''))
            config_file.set_chapter(chapter)

            config_file.set_key('v3_ca', 'basicConstraints',
                                'critical,CA:true')

        config_file.set_key('CA_default', 'dir', self.__capath)
        # lifetime of ca is 10 years
        config_file.set_key('CA_default', 'default_days', '3650')

        # Generic config for both CA and intermediates
        config_file.set_chapter(self.__subject.chapter())
        config_file.set_key('CA_default', 'certificate', self.__cert_file)
        config_file.set_key('CA_default', 'private_key', self.__pem_file)

        if self.__cert_type in ['clientserver', 'client', 'server']:
            config_file.set_key('usr_cert', 'basicConstraints', 'CA:FALSE')
            config_file.set_key('usr_cert', 'subjectKeyIdentifier', 'hash')
        if self.__cert_type == 'clientserver':
            config_file.set_key('usr_cert', 'nsCertType',
                                'client, server, email')
            config_file.set_key('usr_cert', 'nsComment',
                                '"OpenSSL Generated ClientServer Certificate"')
            config_file.set_key('usr_cert', 'authorityKeyIdentifier',
                                'keyid,issuer')
            config_file.set_key('usr_cert', 'keyUsage',
                                'critical, nonRepudiation, digitalSignature, '
                                'keyEncipherment')
            config_file.set_key('usr_cert', 'extendedKeyUsage',
                                'clientAuth, serverAuth, emailProtection')
        elif self.__cert_type == 'client':
            config_file.set_key('usr_cert', 'nsCertType', 'client, email')
            config_file.set_key('usr_cert', 'nsComment',
                                '"OpenSSL Generated Client Certificate"')
            config_file.set_key('usr_cert', 'authorityKeyIdentifier',
                                'keyid,issuer')
            config_file.set_key('usr_cert', 'keyUsage',
                                'critical, nonRepudiation, digitalSignature, '
                                'keyEncipherment')
            config_file.set_key('usr_cert', 'extendedKeyUsage',
                                'clientAuth, emailProtection')
        elif self.__cert_type == 'server':
            config_file.set_key('usr_cert', 'nsCertType', 'server')
            config_file.set_key('usr_cert', 'nsComment',
                                '"OpenSSL Generated Server Certificate"')
            config_file.set_key('usr_cert', 'authorityKeyIdentifier',
                                'keyid,issuer:always')
            config_file.set_key('usr_cert', 'keyUsage',
                                'critical, digitalSignature, keyEncipherment')
            config_file.set_key('usr_cert', 'extendedKeyUsage', 'serverAuth')

        self.log('writing config to ' + self.__config_file)
        config_file.write(self.__config_file)

    def gen_ca_pem(self):
        """Generate a private key for the ca"""
        try:
            self.gen_pem_password()
        except TlsPwdAlreadySetException:
            # This is just a precaution to use a random password if it
            # was not yet set, so if it is, that is totally cool...
            pass

        self.log("Running openssl genrsa for "+self.name())
        args = ['openssl', 'genrsa', '-des3', '-passout',
                'file:' + self.__password_file, '-out', self.__pem_file,
                '4096']
        self.log_command(' '.join(args))
        run(args, cwd=self.__capath, check=True, stdout=self.__stdout,
            stderr=self.__stderr)
        self.verify_pem()

    def verify_pem(self):
        """Verify the private key for the ca"""
        self.log("Running openssl rsa for "+self.name())
        args = ['openssl', 'rsa', '-noout', '-text', '-in',
                self.__pem_file, '-passin',
                'file:' + self.__password_file]
        self.log_command(' '.join(args))
        run(args, cwd=self.__capath, check=True, stdout=self.__stdout,
            stderr=self.__stderr)

    def create_ca_cert(self):
        """Create the cert for this CA"""
        self.gen_ca_cnf()
        self.gen_ca_pem()
        self.log("Running openssl req for "+self.name())
        if self.__parent is None:
            self.log(self.__subject.string())
            args = ['openssl', 'req', '-new', '-x509', '-days', '3650',
                    '-subj', self.__subject.string(), '-passin',
                    'file:' + self.__password_file, '-config',
                    self.__config_file, '-extensions', 'v3_ca', '-key',
                    self.__pem_file, '-out', self.__cert_file]
            self.log_command(' '.join(args))
            run(args, cwd=self.__capath, check=True, stdout=self.__stdout,
                stderr=self.__stderr)
        else:
            csr_path = join(self.__capath, 'csr', 'intermediate.csr.pem')
            args = ['openssl', 'req', '-new', '-sha256', '-subj',
                    self.__subject.string(), '-config', self.__config_file,
                    '-passin', 'file:' + self.__password_file,
                    '-key', self.__pem_file, '-out', csr_path]
            self.log_command(' '.join(args))
            run(args, cwd=self.__capath, check=True, stdout=self.__stdout,
                stderr=self.__stderr)
            self.__parent.sign_intermediate_csr(csr_path, self.__cert_file)
        self.verify_ca_cer()
        self.write_chain()

    def sign_intermediate_csr(self, csr, cert):
        """Sign a csr for a child intermediate of this CA"""
        self.log("Running openssl ca for "+self.name())
        args = ['openssl', 'ca', '-config', self.__config_file,
                '-extensions', 'v3_intermediate_ca', '-days', '2650',
                '-notext', '-batch', '-passin',
                'file:' + self.__password_file, '-in', csr, '-out', cert]
        self.log_command(' '.join(args))
        run(args, cwd=self.__capath, check=True, stdout=self.__stdout,
            stderr=self.__stderr)

    def sign_cert_csr(self, ext_conf, csr_path, cert_path):
        """Sign a csr for a child cert of this CA"""
        # openssl x509 -req -days 3650 -in tls/int_server/csr/server1.csr
        # -signkey tls/int_server/private/cakey.pem
        # -out tls/int_server/certs/server1.pem
        # -extfile tls/int_server/config/req_server1.cnf -extensions v3_req
        # -passin file:/host/tls/int_server/private/capass.enc
        self.log("Running openssl x509 req for "+self.name())
        if self.__cert_type == 'clientserver':
            args = ['openssl', 'x509', '-req', '-in', csr_path, '-passin',
                    'file:' + self.__password_file, '-CA', self.__chain_file,
                    '-CAkey', self.__pem_file, '-out', cert_path,
                    '-CAcreateserial', '-days', '365', '-sha256']
        elif self.__cert_type == 'client':
            args = ['openssl', 'x509', '-req', '-in', csr_path, '-passin',
                    'file:' + self.__password_file, '-CA', self.__chain_file,
                    '-CAkey', self.__pem_file, '-out', cert_path,
                    '-CAcreateserial', '-days', '365', '-sha256']
        elif self.__cert_type == 'server':
            args = ['openssl', 'x509', '-req', '-in', csr_path, '-passin',
                    'file:' + self.__password_file, '-CA',
                    self.__chain_file, '-CAkey', self.__pem_file, '-out',
                    cert_path, '-CAcreateserial', '-days', '365',
                    '-sha256', '-extfile', ext_conf, '-extensions',
                    'v3_req']
        else:
            raise Exception('Unknown intermediate type')
        self.log_command(' '.join(args))
        run(args, cwd=self.__capath, check=True, stdout=self.__stdout,
            stderr=self.__stderr)

    def verify_ca_cer(self):
        """Verify that the certificate for this intermediate is valid"""
        self.log("Running openssl x509 for "+self.name())
        args = ['openssl', 'x509', '-noout', '-text', '-in',
                'certs/cacert.pem']
        self.log_command(' '.join(args))
        run(args, cwd=self.__capath, check=True, stdout=self.__stdout,
            stderr=self.__stderr)

    def get_cert(self):
        """Return the cert of this CA as a string"""
        with open(self.__cert_file, encoding="utf8") as crt:
            return crt.read()

    def get_chain(self):
        """
        Return the cert of his CA with the parents up until the root as a chain
        """
        cert_body = self.get_cert()
        if cert_body[-1] != '\n':
            cert_body += '\n'
        if self.__parent is not None:
            cert_body += self.__parent.get_chain()
        return cert_body

    def get_certs(self):
        """Return a dict containing all certs as strings"""
        certs = {'chain': self.get_chain()}
        for name, cert in self.items():
            certs[name] = cert.get_cert()
        return certs

    def get_private_key(self):
        """Return the private key of tis intermediate as a string"""
        with open(self.__pem_file, encoding="utf8") as pem:
            return pem.read()

    def get_private_keys(self):
        """Return a dict containing all private keys as strings"""
        private_keys = {self.name(): self.get_private_key()}
        for name, cert in self.items():
            private_keys[name] = cert.get_private_key()
        return private_keys

    def write_chain(self):
        """
        Write the chain to a file in the directory containing all
        files for this CA
        """
        try:
            with open(self.__chain_file, 'w', encoding="utf8") as chainfile:
                chainfile.write(self.get_chain())
        except OSError as os_err:
            print("Cannot open file:", os_err)

    def create_int(self, name, cert_type):
        """Create an intermediate as a child for this CA"""
        if self.__parent is not None:
            raise Exception("Creating an intermediate on an intermediate "
                            "is currently not a feature...")
        if name in self:
            return self[name]
        int_path = join(self.__capath, 'int_' + name)
        int_ca = TlsCA(int_path, name, cert_type, self)
        int_ca.set_debug_output(self.__stdout, self.__stderr)
        int_ca.create_ca_cert()
        # For a root CA, all intermediates are stored in the object
        self[name] = int_ca
        return int_ca

    def create_cert(self, san):
        """Create a root cert as a child of his intermediate"""
        if not san:
            return None
        name = san[0]
        if self.__parent is None:
            raise Exception("Creating a certificate signed by a root CA is "
                            "currently not a feature...")
        if name in self:
            return self[name]
        # For an intermediate CA, all certs are stored in the object itself
        cert = TlsCert(san, self.__subject.clone(), self)
        cert.set_debug_output(self.__stdout, self.__stderr)
        cert.gen_pem()
        cert.gen_cnf()
        cert.gen_cert()

        self[name] = cert
        return cert


class TlsCert:
    """
    TlsCert represents a certificate to be handed out.
    This could be a client certificate or a server certificate.
    It works together with its parent (intermediate) for signing the csr.
    """

    # pylint: disable=too-many-instance-attributes
    __name = ""
    __parent = None
    __pem_file = ""
    __subject_alternate_names = None
    __csr_path = ""
    __cert_file = ""
    __subject = ""
    __config_file = ""
    __stdout = stdout
    __stderr = stderr

    def __init__(self, san, subject, parent):
        if not san:
            raise Exception('cannot create TlsCert without at least '
                            'one name in SAN list')
        self.__name = name = san[0]
        self.__parent = parent
        self.__subject_alternate_names = san
        self.__subject = subject
        self.__subject['CN'] = name

        path = parent.path()
        self.__pem_file = join(path, 'private', name + '.key.pem')
        self.__csr_path = join(path, 'csr', name + '.csr')
        self.__cert_file = join(path, 'certs', name + '.pem')
        self.__config_file = join(path, 'config', 'req_' + name + '.cnf')

    def set_debug_output(self, out, err):
        """Set the stdout and stderr to log to"""
        self.__stdout = out
        self.__stderr = err

    def log_command(self, command):
        """log a command that is about to be run"""
        self.__stdout.write(command+':\n')
        self.__stdout.write('='*len(command)+'=\n')

    def log(self, line):
        """Log a line"""
        self.__stdout.write(line+'\n')

    def name(self):
        """Return the name of this cert"""
        return self.__name

    def gen_pem(self):
        """Generate a private key for this certificate"""
        args = ['openssl', 'genrsa', '-out', self.__pem_file, '4096']
        self.log_command(' '.join(args))
        run(args, check=True, stdout=self.__stdout, stderr=self.__stderr)
        self.verify_pem()

    def verify_pem(self):
        """Verify the private key for this certificate"""
        args = ['openssl', 'rsa', '-noout', '-text', '-in', self.__pem_file]
        self.log_command(' '.join(args))
        run(args, check=True, stdout=self.__stdout, stderr=self.__stderr)

    def gen_cnf(self):
        """Generate a config file for this certificate"""
        config_file = ConfigFile(self.__parent.configfile())
        config_file.set_key('req', 'req_extensions', 'v3_req')
        # Generic config for both CA and intermediates
        config_file.set_chapter(self.__subject.chapter())

        config_file.set_key('v3_req', 'keyUsage', ', '.join([
            'keyEncipherment',
            'dataEncipherment',
            'digitalSignature',
        ]))
        config_file.set_key('v3_req', 'extendedKeyUsage', 'serverAuth')

        if len(self.__subject_alternate_names) > 1:
            config_file.set_key('v3_req', 'subjectAltName', '@alt_names')
            dns_counter = ip_counter = 0
            for _, alt_name in enumerate(self.__subject_alternate_names):
                try:
                    ip_address(alt_name)
                    config_file.set_key('alt_names', 'IP.'+str(ip_counter),
                                        alt_name)
                    ip_counter += 1
                except ValueError:
                    config_file.set_key('alt_names', 'DNS.'+str(dns_counter),
                                        alt_name)
                    dns_counter += 1
        self.log('writing config to '+self.__config_file)
        config_file.write(self.__config_file)

    def create_csr(self):
        """Create a certificate signing request from the config file"""
        # openssl req -new -out company_san.csr -newkey rsa:4096 -nodes -sha256
        # -keyout company_san.key.temp -config req.conf
        # # Convert key to PKCS#1
        # openssl rsa -in san.key.temp -out san.key
        # # Add csr in a readable format
        # openssl req -text -noout -verify -in san.csr > san.csr.txt
        args = ['openssl', 'req', '-new', '-subj', self.__subject.string(),
                '-key', self.__pem_file, '-out', self.__csr_path, '-config',
                self.__config_file]
        self.log_command(' '.join(args))
        run(args, check=True, stdout=self.__stdout, stderr=self.__stderr)
        self.verify_csr()

    def verify_csr(self):
        """
        Verify the Certificate Signing Request that was created for this cert
        """
        args = ['openssl', 'req', '-noout', '-text', '-in', self.__csr_path]
        self.log_command(' '.join(args))
        run(args, check=True, stdout=self.__stdout, stderr=self.__stderr)

    def gen_cert(self):
        """Create a CSR and have it signed to become a certificate"""
        self.create_csr()
        self.__parent.sign_cert_csr(self.__config_file, self.__csr_path,
                                    self.__cert_file)
        self.verify_cert()

    def verify_cert(self):
        """Verify the certificate"""
        args = ['openssl', 'x509', '-noout', '-text', '-in', self.__cert_file]
        self.log_command(' '.join(args))
        run(args, check=True, stdout=self.__stdout, stderr=self.__stderr)

    def get_cert(self):
        """Return the certificate as a string"""
        try:
            with open(self.__cert_file, encoding="utf8") as crt:
                return crt.read()
        except OSError as os_err:
            print("Cannot open file:", os_err)
        return None

    def get_private_key(self):
        """Return the private key for this cert as a string"""
        try:
            with open(self.__pem_file, encoding="utf8") as pem:
                return pem.read()
        except OSError as os_err:
            print("Cannot open file:", os_err)
        return None
