import threading

GLOBAL_STATE = None
GLOBAL_STATE_LOCK = threading.Lock()


def set_global_state(value):
    global GLOBAL_STATE
    with GLOBAL_STATE_LOCK:
        GLOBAL_STATE = value


def get_global_state():
    with GLOBAL_STATE_LOCK:
        return GLOBAL_STATE
