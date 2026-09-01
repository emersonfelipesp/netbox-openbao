"""Static contract checks for netbox-rpc integration."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_required_plugins_declares_netbox_rpc():
    init_src = (REPO_ROOT / 'netbox_openbao' / '__init__.py').read_text()
    assert "required_plugins = ['netbox_rpc']" in init_src


def test_pyproject_declares_netbox_rpc_dependency():
    pyproject = (REPO_ROOT / 'pyproject.toml').read_text()
    assert 'netbox-rpc>=' in pyproject


def test_api_exposes_procedure_runs_and_run_procedure_action():
    api_views = (REPO_ROOT / 'netbox_openbao' / 'api' / 'views.py').read_text()
    api_urls = (REPO_ROOT / 'netbox_openbao' / 'api' / 'urls.py').read_text()
    assert 'OpenBaoProcedureRunViewSet' in api_views
    assert 'run_procedure' in api_views
    assert 'procedure-runs' in api_urls
    assert 'netbox_rpc.execute_rpcprocedure' not in api_views


def test_rpc_module_dispatches_through_create_execution():
    rpc_src = (REPO_ROOT / 'netbox_openbao' / 'rpc.py').read_text()
    assert 'create_execution' in rpc_src
    assert 'dispatch_openbao_procedure' in rpc_src
