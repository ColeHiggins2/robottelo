import logging
from functools import partial

from wait_for import wait_for as wait_for_mod
from wait_for import wait_for_decorator as wait_for_decorator_mod

wait_for = partial(wait_for_mod, logger=logging)
wait_for_decorator = partial(wait_for_decorator_mod, logger=logging)
