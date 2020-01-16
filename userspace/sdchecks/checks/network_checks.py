# stdlib
# project
from builtins import object
from checks import AgentCheck

TIMEOUT = 180
DEFAULT_SIZE_POOL = 6
MAX_LOOP_ITERATIONS = 1000
FAILURE = "FAILURE"


class Status(object):
    DOWN = "DOWN"
    WARNING = "WARNING"
    UP = "UP"


class EventType(object):
    DOWN = "servicecheck.state_change.down"
    UP = "servicecheck.state_change.up"


class NetworkCheck(object):
    SOURCE_TYPE_NAME = 'servicecheck'
    SERVICE_CHECK_PREFIX = 'network_check'

    STATUS_TO_SERVICE_CHECK = {
        Status.UP  : AgentCheck.OK,
        Status.WARNING : AgentCheck.WARNING,
        Status.DOWN : AgentCheck.CRITICAL
    }
