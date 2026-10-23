"""
Test for Issue 1: Render deployment configuration.
Verifies that:
- run.py exposes 'app' (Flask application instance)
- render.yaml specifies buildCommand 'bash build.sh' and sets FLASK_APP=run.py
- build.sh sets FLASK_APP and calls flask with --app run.py
"""
import os
import run
from flask import Flask


def test_run_py_exposes_app():
    """Confirm run.py exposes a valid Flask WSGI application instance."""
    assert hasattr(run, 'app')
    assert isinstance(run.app, Flask)
    assert run.app.name == 'app'


def test_render_yaml_configuration():
    """Confirm render.yaml uses bash build.sh and sets FLASK_APP=run.py."""
    with open('render.yaml', 'r') as f:
        content = f.read()

    assert 'buildCommand: "bash build.sh"' in content
    assert 'key: FLASK_APP' in content
    assert 'value: run.py' in content


def test_build_sh_configuration():
    """Confirm build.sh sets FLASK_APP=run.py and uses --app run.py."""
    with open('build.sh', 'r') as f:
        content = f.read()

    assert 'export FLASK_APP=run.py' in content
    assert '--app run.py' in content
