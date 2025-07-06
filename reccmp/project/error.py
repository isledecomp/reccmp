class RecCmpProjectException(Exception):
    pass


class RecCmpProjectNotFoundException(RecCmpProjectException):
    pass


class InvalidRecCmpProjectException(RecCmpProjectException):
    pass


class InvalidRecCmpArgumentException(RecCmpProjectException):
    pass


class UnknownRecCmpTargetException(RecCmpProjectException):
    pass


class IncompleteReccmpTargetError(RecCmpProjectException):
    pass
