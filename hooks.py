def connected(function):
    """
    Decorator that checks the api status
    before doing any request
    """
    def check_connection(self, *args, **kwargs):
        if self.api is None or self.api.authSubToken is None:
            ok, err = self.connect()
            if not ok:
                exit(err)
        return function(self, *args, **kwargs)
    return check_connection
