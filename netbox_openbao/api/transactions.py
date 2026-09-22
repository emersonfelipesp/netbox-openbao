"""Preserve native error responses only after a confirmed owned rollback."""

from functools import wraps
from typing import Any

from django.views.decorators.debug import sensitive_variables
from rest_framework import status
from rest_framework.response import Response

from netbox_openbao.backends.exceptions import OpenBaoError, OpenBaoMutationUnknown
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
        except OpenBaoMutationUnknown:
            response = Response({
                'outcome': 'unknown',
                'message': 'OpenBao may have accepted the request. Do not retry; verify current state first.',
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
            response['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
            response['X-OpenBao-Operation-Outcome'] = 'unknown'
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
