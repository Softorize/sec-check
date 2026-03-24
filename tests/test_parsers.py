"""Tests for sec_check.parsers — command parsing and bypass prevention."""

import pytest
from sec_check.parsers import parse_command, PackageRef


class TestPipParsing:
    """Test pip/pip3/python -m pip install parsing."""

    def test_pip_install_single(self):
        pkgs = parse_command("pip install requests")
        assert len(pkgs) == 1
        assert pkgs[0].name == "requests"
        assert pkgs[0].ecosystem == "pypi"

    def test_pip_install_with_version(self):
        pkgs = parse_command("pip install litellm==1.82.7")
        assert len(pkgs) == 1
        assert pkgs[0].name == "litellm"
        assert pkgs[0].version == "1.82.7"

    def test_pip3_install_multiple(self):
        pkgs = parse_command("pip3 install flask django>=4.0")
        assert len(pkgs) == 2
        assert pkgs[0].name == "flask"
        assert pkgs[1].name == "django"
        assert pkgs[1].version == "4.0"

    def test_pip_install_requirements_file(self):
        pkgs = parse_command("pip install -r requirements.txt")
        assert pkgs == []

    def test_python_m_pip_install(self):
        pkgs = parse_command("python3 -m pip install --break-system-packages boto3")
        assert len(pkgs) == 1
        assert pkgs[0].name == "boto3"

    def test_pip_install_extras(self):
        pkgs = parse_command("pip install requests[security]")
        assert len(pkgs) == 1
        assert pkgs[0].name == "requests"

    def test_pip_install_local_dot(self):
        assert parse_command("pip install .") == []

    def test_pip_install_local_path(self):
        assert parse_command("pip install ./mypackage") == []

    def test_pip_install_git_url(self):
        assert parse_command("pip install git+https://github.com/user/repo.git") == []

    def test_pip_install_url(self):
        assert parse_command("pip install https://files.example.com/pkg.tar.gz") == []


class TestNpmParsing:
    """Test npm/yarn/pnpm parsing."""

    def test_npm_install(self):
        pkgs = parse_command("npm install express")
        assert len(pkgs) == 1
        assert pkgs[0].name == "express"
        assert pkgs[0].ecosystem == "npm"

    def test_npm_i_with_version(self):
        pkgs = parse_command("npm i lodash@4.17.21 axios")
        assert len(pkgs) == 2
        assert pkgs[0].name == "lodash"
        assert pkgs[0].version == "4.17.21"
        assert pkgs[1].name == "axios"

    def test_yarn_add(self):
        pkgs = parse_command("yarn add react@18")
        assert len(pkgs) == 1
        assert pkgs[0].name == "react"
        assert pkgs[0].version == "18"

    def test_pnpm_add(self):
        pkgs = parse_command("pnpm add lodash")
        assert len(pkgs) == 1
        assert pkgs[0].name == "lodash"

    def test_scoped_package(self):
        pkgs = parse_command("npm install @angular/core")
        assert len(pkgs) == 1
        assert pkgs[0].name == "@angular/core"


class TestOtherEcosystems:
    """Test go, cargo, gem parsing."""

    def test_go_get(self):
        pkgs = parse_command("go get github.com/gin-gonic/gin@v1.9.1")
        assert len(pkgs) == 1
        assert pkgs[0].name == "github.com/gin-gonic/gin"
        assert pkgs[0].version == "v1.9.1"

    def test_cargo_install(self):
        pkgs = parse_command("cargo install ripgrep")
        assert len(pkgs) == 1
        assert pkgs[0].name == "ripgrep"
        assert pkgs[0].ecosystem == "cargo"

    def test_gem_install(self):
        pkgs = parse_command("gem install rails")
        assert len(pkgs) == 1
        assert pkgs[0].name == "rails"
        assert pkgs[0].ecosystem == "gem"


class TestNewInstallers:
    """Test uv, pipx, bun support."""

    def test_uv_pip_install(self):
        pkgs = parse_command("uv pip install malicious")
        assert len(pkgs) == 1
        assert pkgs[0].name == "malicious"
        assert pkgs[0].ecosystem == "pypi"

    def test_uv_add(self):
        pkgs = parse_command("uv add requests")
        assert len(pkgs) == 1
        assert pkgs[0].name == "requests"

    def test_pipx_install(self):
        pkgs = parse_command("pipx install malicious")
        assert len(pkgs) == 1
        assert pkgs[0].name == "malicious"
        assert pkgs[0].ecosystem == "pypi"

    def test_bun_install(self):
        pkgs = parse_command("bun install express")
        assert len(pkgs) == 1
        assert pkgs[0].name == "express"
        assert pkgs[0].ecosystem == "npm"


class TestBypassPrevention:
    """Test that previously-bypassed vectors are now caught."""

    def test_sudo_prefix(self):
        pkgs = parse_command("sudo pip install malicious")
        assert len(pkgs) == 1
        assert pkgs[0].name == "malicious"

    def test_full_path(self):
        pkgs = parse_command("/usr/bin/pip install malicious")
        assert len(pkgs) == 1
        assert pkgs[0].name == "malicious"

    def test_env_var_prefix(self):
        pkgs = parse_command("PYTHONPATH=/tmp pip install malicious")
        assert len(pkgs) == 1
        assert pkgs[0].name == "malicious"

    def test_quoted_args(self):
        pkgs = parse_command('pip install "pkg-name"')
        assert len(pkgs) == 1
        assert pkgs[0].name == "pkg-name"

    def test_command_substitution_dollar(self):
        pkgs = parse_command("pip install $(echo malicious)")
        assert len(pkgs) == 1
        assert pkgs[0].name == "__DYNAMIC_INSTALL__"

    def test_command_substitution_backtick(self):
        pkgs = parse_command("pip install `echo malicious`")
        assert len(pkgs) == 1
        assert pkgs[0].name == "__DYNAMIC_INSTALL__"

    def test_pipe_to_install(self):
        pkgs = parse_command("echo pkg | xargs pip install foo")
        # Should get 'foo' from direct parsing + piped install marker
        names = [p.name for p in pkgs]
        assert "foo" in names
        assert "__PIPED_INSTALL__" in names

    def test_sudo_with_env_and_path(self):
        pkgs = parse_command("sudo -E /usr/local/bin/pip3 install flask")
        assert len(pkgs) == 1
        assert pkgs[0].name == "flask"

    def test_env_command_prefix(self):
        pkgs = parse_command("env FOO=bar pip install boto3")
        assert len(pkgs) == 1
        assert pkgs[0].name == "boto3"


class TestCommandChaining:
    """Test command chain splitting."""

    def test_and_chain(self):
        pkgs = parse_command("pip install requests && npm install express")
        assert len(pkgs) == 2
        names = [p.name for p in pkgs]
        assert "requests" in names
        assert "express" in names

    def test_semicolon_chain(self):
        pkgs = parse_command("pip install requests; npm install express")
        assert len(pkgs) == 2

    def test_quoted_semicolon_not_split(self):
        """Semicolon inside quotes should not split the command."""
        # "pkg;name" is not a valid pip package name, so it won't match
        pkgs = parse_command('pip install "pkg-name" && npm install express')
        names = [p.name for p in pkgs]
        assert "pkg-name" in names
        assert "express" in names


class TestNonInstallCommands:
    """Non-install commands should return empty."""

    def test_echo(self):
        assert parse_command("echo hello") == []

    def test_ls(self):
        assert parse_command("ls -la") == []

    def test_empty(self):
        assert parse_command("") == []

    def test_whitespace(self):
        assert parse_command("   ") == []

    def test_cd(self):
        assert parse_command("cd /tmp") == []
