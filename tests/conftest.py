import pytest

from mon.api import app
from mon.auth import Principal, Role, get_principal


@pytest.fixture(autouse=True)
def authenticated_platform_admin():
    app.dependency_overrides[get_principal] = lambda: Principal(
        subject="pytest-platform-admin",
        roles={Role.PLATFORM_ADMIN},
    )
    yield
    app.dependency_overrides.pop(get_principal, None)
