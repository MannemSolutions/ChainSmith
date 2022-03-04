from os import makedirs
from os.path import join, realpath, expanduser, exists
from string import digits, ascii_uppercase
from random import choice
from tempfile import NamedTemporaryFile
from subprocess import run

from lib.exceptions import TlsPwdAlreadySetException
from lib.config import ConfigFile, ConfigLine, ConfigChapter


class TlsSubject(dict):
    """
    TlsSubject is a small helper class to wrap, unwrap and merge tls subjects that have a form of:
       "/C=US/ST=Utah/L=Lehi/O=Your Company, Inc./OU=IT/CN=yourdomain.com"
    """

    def __init__(self, subject):
        super().__init__()
        if isinstance(subject, str):
            for kv in subject.split('/'):
                if '=' in kv:
                    k, v = kv.split('=', 2)
                    self[k] = v
        else:
            for k, v in subject.items():
                self[k] = v

    def string(self):
        return '/' + '/'.join(['{}={}'.format(k, v) for k, v in self.items()])

    def merge(self, other):
        for k, v in other.items():
            self[k] = v

    def clone(self):
        c = TlsSubject('')
        for k, v in self.items():
            c[k] = v
        return c

    def chapter(self):
        c = ConfigChapter('req_distinguished_name')
        for k, v in self.items():
            c.append(ConfigLine('{} = {}'.format(k, v)))
        c.append(ConfigLine(''))
        return c


class TlsCA(dict):
    """
    TlsCA represents a certificate authority, either root or intermediate.
    It just is a placeholder for the folder, directories, config files, etc.
    And it has methods to create all, sign sub certificates, generate private keys, etc.
    if __parent is None, it is a root certificate, if not, it is a intermediate certificate.
    The class can be used to setup a CA store, and use it to sign requests for lower certificates.
    """
    __capath = ''
    __name = ''
    __cert_type = ''
    __configFile = ''
    __PEMFile = ''
    __passwordFile = ''
    __certFile = ''
    __chainFile = ''
    __subject = None
    __parent = None

    def __init__(self, capath, name, cert_type, parent):
        super().__init__()
        self.__capath = capath
        self.__name = name
        self.__cert_type = cert_type
        self.__configFile = join(capath, 'config', 'ca.cnf')
        self.__PEMFile = join(capath, 'private', 'cakey.pem')
        self.__passwordFile = join(capath, 'private', 'capass.enc')
        self.__certFile = join(capath, 'certs', 'cacert.pem')
        self.__chainFile = join(capath, 'certs', 'ca-chain-bundle.cert.pem')
        try:
            if parent is not None:
                self.set_subject(parent.__subject)
                self.__parent = parent
            for folder in ['.', 'config', 'certs', 'csr', 'newcerts', 'private']:
                path = realpath(expanduser(join(capath, folder)))
                if not exists(path):
                    makedirs(path)
            serial_file = join(capath, 'serial')
            if not exists(serial_file):
                with open(serial_file, 'w') as serial:
                    serial.write('01')
            index_file = join(capath, 'index.txt')
            if not exists(index_file):
                open(index_file, 'w')
        except OSError as os_err:
            print("Cannot open file:", os_err)

    def name(self):
        return self.__name

    def gen_pem_password(self, password=None):
        if exists(self.__passwordFile):
            raise TlsPwdAlreadySetException(self.__passwordFile, "already exists, not replacing")
        if not password:
            password = ''.join(choice(ascii_uppercase + digits) for _ in range(18))
            print('using a random password for', self.name(), 'pem: ', password)
        # This creates a tempfile, writes the password to it, creates the enc file and removes the tempfile
        # as atomic as possible
        try:
            with NamedTemporaryFile(mode='w') as tmpFile:
                tmpFile.write(password)
                tmpFile.flush()
                print("Running openssl genrsa for", self.name())
                args = ['openssl', 'enc', '-aes256', '-salt', '-in', tmpFile.name, '-out', self.__passwordFile, '-pass',
                        'file:'+tmpFile.name]
                run(args)
        except OSError as os_err:
            print("Cannot open file:", os_err)

    def set_subject(self, subject):
        self.__subject = subject.clone()
        self.__subject['CN'] = self.name()

    def subject(self):
        return self.__subject.clone()

    def path(self):
        return self.__capath

    def configfile(self):
        return self.__configFile

    def gen_ca_cnf(self):
        if self.__parent is not None:
            cf = ConfigFile(self.__parent.configfile())
            cf.set_key('CA_default', 'dir', self.__capath)
            cf.set_key('CA_default', 'policy', 'policy_anything')
            cf.set_key('CA_default', 'default_days', '3650')
            # req_attributes contains _min and _max values that help with prompt=yes, but not with prompt=no
            # so resetting to empty chapter
            cf.set_chapter(ConfigChapter('req_attributes'))
        else:
            cf = ConfigFile('/etc/pki/tls/openssl.cnf')
            cf.set_key('req', 'prompt', 'no')
            # cf.set_key('', 'HOME', '.')
            # cf.set_key('', 'RANDFILE', '$ENV::HOME/.rnd')
            # cf.set_key('', 'oid_section', 'new_oids')
            if exists('/etc/crypto-policies/back-ends/opensslcnf.config'):
                # seems to have something to do with FIPS mode on RH8. For more info see
                # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/using-the-system-wide-cryptographic-policies_security-hardening
                cf.set_key('', 'openssl_conf', 'default_modules')
                cf.set_key('default_modules', 'ssl_conf', 'ssl_module')
                cf.set_key('ssl_module', 'system_default', 'crypto_policy')
                cf.set_key('crypto_policy', '.include /etc/crypto-policies/back-ends/opensslcnf.config', '')

            cf.set_key('CA_default', 'dir', self.__capath)
            # lifetime of ca is 10 years
            cf.set_key('CA_default', 'default_days', '3650')
            # cf.set_key('CA_default', 'policy', 'policy_match')

            cf.set_key('req', 'default_bits', '4096')

            intermediate_chapter = ConfigChapter('v3_intermediate_ca')
            intermediate_chapter.append(ConfigLine('subjectKeyIdentifier = hash'))
            intermediate_chapter.append(ConfigLine('authorityKeyIdentifier = keyid:always,issuer'))
            intermediate_chapter.append(ConfigLine('basicConstraints = critical, CA:true, pathlen:0'))
            intermediate_chapter.append(ConfigLine('keyUsage = critical, digitalSignature, cRLSign, keyCertSign'))
            intermediate_chapter.append(ConfigLine(''))
            cf.set_chapter(intermediate_chapter)

            cf.set_key('v3_ca', 'basicConstraints', 'critical,CA:true')

        # Generic config for both CA and intermediates
        cf.set_chapter(self.__subject.chapter())
        cf.set_key('CA_default', 'certificate', self.__certFile)
        cf.set_key('CA_default', 'private_key', self.__PEMFile)

        if self.__cert_type in ['client', 'server']:
            cf.set_key('usr_cert', 'basicConstraints', 'CA:FALSE')
            cf.set_key('usr_cert', 'subjectKeyIdentifier', 'hash')
        if self.__cert_type == 'client':
            cf.set_key('usr_cert', 'nsCertType', 'client, email')
            cf.set_key('usr_cert', 'nsComment', '"OpenSSL Generated Client Certificate"')
            cf.set_key('usr_cert', 'authorityKeyIdentifier', 'keyid,issuer')
            cf.set_key('usr_cert', 'keyUsage', 'critical, nonRepudiation, digitalSignature, keyEncipherment')
            cf.set_key('usr_cert', 'extendedKeyUsage', 'clientAuth, emailProtection')
        elif self.__cert_type == 'server':
            cf.set_key('usr_cert', 'nsCertType', 'server')
            cf.set_key('usr_cert', 'nsComment', '"OpenSSL Generated Server Certificate"')
            cf.set_key('usr_cert', 'authorityKeyIdentifier', 'keyid,issuer:always')
            cf.set_key('usr_cert', 'keyUsage', 'critical, digitalSignature, keyEncipherment')
            cf.set_key('usr_cert', 'extendedKeyUsage', 'serverAuth')

        print('writing config to', self.__configFile)
        cf.write(self.__configFile)

    def gen_ca_pem(self):
        try:
            self.gen_pem_password()
        except TlsPwdAlreadySetException:
            # This is just a precaution to use a random password if it was not yet set, so if it is, that is totally
            # cool...
            pass

        print("Running openssl genrsa for", self.name())
        args = ['openssl', 'genrsa', '-des3', '-passout', 'file:' + self.__passwordFile, '-out', self.__PEMFile, '4096']
        run(args, cwd=self.__capath, check=True)
        self.verify_pem()

    def verify_pem(self):
        print("Running openssl rsa for", self.name())
        args = ['openssl', 'rsa', '-noout', '-text', '-in', self.__PEMFile, '-passin', 'file:' + self.__passwordFile]
        run(args, cwd=self.__capath, check=True)

    def create_ca_cert(self):
        self.gen_ca_cnf()
        self.gen_ca_pem()
        print("Running openssl req for", self.name())
        if self.__parent is None:
            print(self.__subject.string())
            args = ['openssl', 'req', '-new', '-x509', '-days', '3650', '-subj', self.__subject.string(), '-passin',
                    'file:' + self.__passwordFile, '-config', self.__configFile, '-extensions', 'v3_ca', '-key',
                    self.__PEMFile, '-out', self.__certFile]
            run(args, cwd=self.__capath, check=True)
        else:
            csr_path = join(self.__capath, 'csr', 'intermediate.csr.pem')
            args = ['openssl', 'req', '-new', '-sha256', '-subj', self.__subject.string(), '-config', self.__configFile,
                    '-passin', 'file:' + self.__passwordFile, '-key', self.__PEMFile, '-out', csr_path]
            run(args, cwd=self.__capath, check=True)
            self.__parent.sign_intermediate_csr(csr_path, self.__certFile)
        self.verify_ca_cer()
        self.write_chain()

    def sign_intermediate_csr(self, csr, cert):
        print("Running openssl ca for", self.name())
        args = ['openssl', 'ca', '-config', self.__configFile, '-extensions', 'v3_intermediate_ca', '-days', '2650',
                '-notext', '-batch', '-passin', 'file:' + self.__passwordFile, '-in', csr, '-out', cert]
        run(args, cwd=self.__capath, check=True)

    def sign_cert_csr(self, ext_conf, csr_path, cert_path):
        # openssl x509 -req -days 3650 -in tls/int_server/csr/server1.csr -signkey tls/int_server/private/cakey.pem
        # -out tls/int_server/certs/server1.pem -extfile tls/int_server/config/req_server1.cnf -extensions v3_req
        # -passin file:/host/tls/int_server/private/capass.enc
        print("Running openssl x509 req for", self.name())
        if self.__cert_type == 'client':
            args = ['openssl', 'x509', '-req', '-in', csr_path, '-passin', 'file:' + self.__passwordFile, '-CA',
                    self.__chainFile, '-CAkey', self.__PEMFile, '-out', cert_path, '-CAcreateserial', '-days', '365',
                    '-sha256']
        elif self.__cert_type == 'server':
            args = ['openssl', 'x509', '-req', '-in', csr_path, '-passin', 'file:' + self.__passwordFile, '-CA',
                    self.__chainFile, '-CAkey', self.__PEMFile, '-out', cert_path, '-CAcreateserial', '-days', '365',
                    '-sha256', '-extfile', ext_conf, '-extensions', 'v3_req']
        else:
            raise Exception('Unknown intermediate type')
        print(args)
        run(args, cwd=self.__capath, check=True)

    def verify_ca_cer(self):
        print("Running openssl x509 for", self.name())
        args = ['openssl', 'x509', '-noout', '-text', '-in', 'certs/cacert.pem']
        run(args, cwd=self.__capath, check=True)

    def get_cert(self):
        with open(self.__certFile) as crt:
            return crt.read()

    def get_chain(self):
        s = self.get_cert()
        if s[-1] != '\n':
            s += '\n'
        if self.__parent is not None:
            s += self.__parent.get_chain()
        return s

    def get_certs(self):
        certs = {'chain': self.get_chain()}
        for name, cert in self.items():
            certs[name] = cert.get_cert()
        return certs

    def get_pem(self):
        with open(self.__PEMFile) as pem:
            return pem.read()

    def get_pems(self):
        pems = {self.name(): self.get_pem()}
        for name, cert in self.items():
            pems[name] = cert.get_pem()
        return pems

    def write_chain(self):
        try:
            with open(self.__chainFile, 'w') as chainfile:
                chainfile.write(self.get_chain())
        except OSError as os_err:
            print("Cannot open file:", os_err)

#    def verify_chain(self):
#        args = ['openssl', 'verify', '-CAfile', self.__certFile, 'intermediate/certs/ca-chain-bundle.cert.pem']
#        run(args, cwd=self.__capath, check=True)
#
    def create_int(self, name, cert_type):
        if self.__parent is not None:
            raise Exception("Creating an intermediate on an intermediate is currently not a feature...")
        if name in self:
            return self[name]
        int_path = join(self.__capath, 'int_' + name)
        int_ca = TlsCA(int_path, name, cert_type, self)
        int_ca.create_ca_cert()
        # For a root CA, all intermediates are stored in the object
        self[name] = int_ca
        return int_ca

    def create_cert(self, san):
        if not san:
            return
        name = san[0]
        if self.__parent is None:
            raise Exception("Creating a certificate signed by a root CA is currently not a feature...")
        if name in self:
            return self[name]
        # For an intermediate CA, all certs are stored in the object itself
        cert = TlsCert(san, self.__subject.clone(), self)
        self[name] = cert
        return cert


class TlsCert:
    """
    TlsCert represents a certificate to be handed out. This could be a client certificate or a server certificate.
    It works together with its parent (typically a intermediate ca) for signing the csr.
    """
    __name = ""
    __parent = None
    __PEMFile = ""
    __SAN = None
    __CSRPath = ""
    __certFile = ""
    __subject = ""
    __configFile = ""

    def __init__(self, san, subject, parent):
        if not san:
            raise Exception('cannot create TlsCert without at least one name in SAN list')
        self.__name = name = san[0]
        self.__parent = parent
        self.__SAN = san
        self.__subject = subject
        self.__subject['CN'] = name

        path = parent.path()
        self.__PEMFile = join(path, 'private', name + '.key.pem')
        self.__CSRPath = join(path, 'csr', name + '.csr')
        self.__certFile = join(path, 'certs', name + '.pem')
        self.__configFile = join(path, 'config', 'req_' + name + '.cnf')

        self.gen_pem()
        self.gen_cnf()
        self.gen_cert()

    def name(self):
        return self.__name

    def gen_pem(self):
        args = ['openssl', 'genrsa', '-out', self.__PEMFile, '4096']
        run(args, check=True)
        self.verify_pem()

    def verify_pem(self):
        args = ['openssl', 'rsa', '-noout', '-text', '-in', self.__PEMFile]
        run(args, check=True)

    def gen_cnf(self):
        cf = ConfigFile(self.__parent.configfile())
        cf.set_key('req', 'req_extensions', 'v3_req')
        # Generic config for both CA and intermediates
        cf.set_chapter(self.__subject.chapter())

        cf.set_key('v3_req', 'keyUsage', 'keyEncipherment, dataEncipherment')
        cf.set_key('v3_req', 'extendedKeyUsage', 'serverAuth')

        if len(self.__SAN) > 1:
            cf.set_key('v3_req', 'subjectAltName', '@alt_names')
            for i in range(len(self.__SAN)):
                if i == 0:
                    # san[0] is already set as CommonName
                    continue
                cf.set_key('alt_names', 'DNS.'+str(i), self.__SAN[i])

        print('writing config to', self.__configFile)
        cf.write(self.__configFile)

    def create_csr(self):
        # openssl req -new -out company_san.csr -newkey rsa:4096 -nodes -sha256 -keyout company_san.key.temp -config
        # req.conf
        # # Convert key to PKCS#1
        # openssl rsa -in company_san.key.temp -out company_san.key
        # # Add csr in a readable format
        # openssl req -text -noout -verify -in company_san.csr > company_san.csr.txt
        args = ['openssl', 'req', '-new', '-subj', self.__subject.string(), '-key', self.__PEMFile, '-out',
                self.__CSRPath, '-config', self.__configFile]
        run(args, check=True)
        self.verify_csr()

    def verify_csr(self):
        args = ['openssl', 'req', '-noout', '-text', '-in', self.__CSRPath]
        run(args, check=True)

    def gen_cert(self):
        self.create_csr()
        self.__parent.sign_cert_csr(self.__configFile, self.__CSRPath, self.__certFile)
        self.verify_cert()

    def verify_cert(self):
        args = ['openssl', 'x509', '-noout', '-text', '-in', self.__certFile]
        run(args, check=True)

    def get_cert(self):
        try:
            with open(self.__certFile) as crt:
                return crt.read()
        except OSError as os_err:
            print("Cannot open file:", os_err)

    def get_pem(self):
        try:
            with open(self.__PEMFile) as pem:
                return pem.read()
        except OSError as os_err:
            print("Cannot open file:", os_err)
