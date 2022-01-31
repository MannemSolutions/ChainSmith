class TlsPwdAlreadySetException(Exception):
    """
    This exception will be raised the gen_pem_password method is run a second time.
    """
    pass