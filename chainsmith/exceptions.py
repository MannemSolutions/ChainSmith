"""
The exceptions that could be raised by the tls module
"""


class TlsPwdAlreadySetException(Exception):
    """
    This exception will be raised the gen_pem_password method runs for
    a second time.
    """
