"""An in-memory SecretBackend, so tests never need a live OpenBao."""

from netbox_openbao.backends.base import SecretBackend
from netbox_openbao.backends.exceptions import OpenBaoConflict, OpenBaoNotFound

__all__ = ('FakeBackend', 'install_fake_backend')


class FakeBackend(SecretBackend):
    """Mimics KV v2 semantics closely enough to exercise check-and-set."""

    store = {}
    metadata = {}
    fail_on_write = False
    fail_on_metadata = False
    delete_calls = []

    def __init__(self, engine, env_prefix=None):
        super().__init__(engine, env_prefix=env_prefix)

    @classmethod
    def reset(cls):
        cls.store = {}
        cls.metadata = {}
        cls.fail_on_write = False
        cls.fail_on_metadata = False
        cls.delete_calls = []

    def read(self, path, version=None):
        versions = self.store.get(path)
        if not versions:
            raise OpenBaoNotFound()
        if version is None:
            return dict(versions[-1])
        try:
            return dict(versions[version - 1])
        except IndexError:
            raise OpenBaoNotFound() from None

    def write(self, path, data, cas=None):
        if self.fail_on_write:
            raise OpenBaoConflict()
        versions = self.store.setdefault(path, [])
        if cas is not None and cas != len(versions):
            raise OpenBaoConflict()
        versions.append(dict(data))
        return len(versions)

    def delete(self, path, versions=None):
        self.delete_calls.append(path)
        self.store.pop(path, None)
        self.metadata.pop(path, None)

    def list_versions(self, path):
        versions = self.store.get(path) or []
        return [{'version': i + 1, 'created_time': None, 'deletion_time': None, 'destroyed': False}
                for i in range(len(versions))][::-1]

    def read_metadata(self, path):
        if path not in self.store:
            raise OpenBaoNotFound()
        return {
            'current_version': len(self.store[path]),
            'custom_metadata': self.metadata.get(path, {}),
        }

    def set_metadata(self, path, metadata):
        if self.fail_on_metadata:
            raise OpenBaoConflict()
        self.metadata[path] = dict(metadata)

    def health(self):
        from netbox_openbao.choices import EngineStatusChoices
        return {'status': EngineStatusChoices.STATUS_HEALTHY, 'message': 'Version test.', 'raw': {}}


def install_fake_backend(monkeypatch_target=None):
    """Point the backend registry at FakeBackend for the duration of a test."""
    from netbox_openbao import backends

    FakeBackend.reset()
    backends.BACKENDS['openbao'] = FakeBackend
    return FakeBackend
