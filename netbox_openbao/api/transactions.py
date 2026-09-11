"""Preserve native error responses only after a confirmed owned rollback."""

from functools import wraps
from typing import Any

from django.views.decorators.debug import sensitive_variables

from netbox_openbao.backends.exceptions import OpenBaoError
from netbox_openbao.material_transactions import material_transaction


def material_api_operation(function: Any) -> Any:
    @wraps(function)
    @sensitive_variables()
    def owned(*args: Any, **kwargs: Any) -> Any:
        response = None
        owner = None
        try:
            with material_transaction() as owner:
                response = function(*args, **kwargs)
            return response
        except OpenBaoError:
            # NetBox can return a batch error after rolling back its savepoint.
            # The outer witness must still trigger compensation, but must not
            # replace that native refusal with a 500. Never preserve success or
            # return a normal refusal after an unknown/committed outcome.
            if owner is not None and owner.known_rollback and response is not None and response.status_code >= 400:
                return response
            raise
    return owned
