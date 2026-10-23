"""
Test for Issue 7:
- Verify that duplicate app/extensions.py has been removed.
- Verify single canonical extensions module at repository root provides db, login_manager, csrf.
- Verify that attempting to import app.extensions fails with ModuleNotFoundError.
"""

import os
import pytest


def test_app_extensions_does_not_exist():
    """Verify that app/extensions.py does not exist on disk."""
    app_extensions_path = os.path.join(os.path.dirname(__file__), '..', 'app', 'extensions.py')
    assert not os.path.exists(app_extensions_path), "Duplicate app/extensions.py must be deleted"


def test_canonical_root_extensions_import():
    """Verify that extensions.py at root provides db, login_manager, and csrf."""
    import extensions
    assert hasattr(extensions, 'db')
    assert hasattr(extensions, 'login_manager')
    assert hasattr(extensions, 'csrf')


def test_import_app_extensions_fails():
    """Verify that importing app.extensions raises ModuleNotFoundError."""
    with pytest.raises(ModuleNotFoundError):
        import app.extensions  # noqa: F401
