#!/usr/bin/python3
#
# Copyright (C) 2025 Simon Gaiser <simon@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License along
# with this program; if not, see <http://www.gnu.org/licenses/>.

import unittest
import tempfile
import subprocess
import os
import re
import struct

from typing import Dict, IO


class DidNotTerminate(AssertionError):
    def __init__(self) -> None:
        super().__init__("splitgpg2 service did not terminate")


# Test that the splitgpg2 service terminates itself as expected. IO happens
# through stdin/-out when called from qrexec. This behaves a bit differently
# than the Unix socket we use for other tests (for example on close). So
# instead start the service script directly.
class TC_Termination(unittest.TestCase):
    @staticmethod
    def path_prepend(env: Dict[str, str], name: str, value: str) -> None:
        if name in env:
            env[name] = ":".join([value, env[name]])
        else:
            env[name] = value

    def setUp(self) -> None:
        super().setUp()

        self.test_env = os.environ.copy()

        self.tmp_dir = tempfile.TemporaryDirectory()

        gpg_home = self.tmp_dir.name + "/gpg-home"
        self.test_env["GNUPGHOME"] = gpg_home
        os.mkdir(gpg_home, mode=0o700)

        xdg_conf_dir = self.tmp_dir.name + "/xdg-config"
        os.mkdir(xdg_conf_dir)
        self.test_env["XDG_CONFIG_HOME"] = xdg_conf_dir

        splitgpg2_conf_dir = xdg_conf_dir + "/qubes-split-gpg2"
        os.mkdir(splitgpg2_conf_dir)

        with open(splitgpg2_conf_dir + "/qubes-split-gpg2.conf", "wb") as f:
            f.write(b"[DEFAULT]\nsource_keyring_dir = no\n")

        path_dir = self.tmp_dir.name + "/path"
        os.mkdir(path_dir)
        self.path_prepend(self.test_env, "PATH", path_dir)

        notify_path = path_dir + "/notify-send"
        with open(notify_path, "wb") as f:
            f.write(b"#!/bin/sh\n")
        os.chmod(notify_path, 0o755)

        self.test_env["QREXEC_REMOTE_DOMAIN"] = "testvm"

        top_dir = os.path.dirname(os.path.dirname(__file__))
        self.path_prepend(self.test_env, "PYTHONPATH", top_dir)

        service_path = top_dir + "/qubes.Gpg2.service"

        # pybuild copies us somewhere else and while you can specify extra
        # files in debian/pybuild.testfiles it executable bit when copying. So
        # fix it.
        if "PYBUILD_NAME" in os.environ:
            os.chmod(service_path, 0o755)

        self.service = subprocess.Popen(
            [service_path],
            env=self.test_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )

        # Make mypy happy:
        assert self.service.stdin is not None
        self.service_stdin = self.service.stdin
        assert self.service.stdout is not None
        self.service_stdout = self.service.stdout

        self.addCleanup(self.cleanup_service)

        self.assertRegex(self.read_line(), rb"\AOK\s")

    def tearDown(self) -> None:
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=self.test_env)
        self.tmp_dir.cleanup()
        super().tearDown()

    def cleanup_service(self) -> None:
        self.service_stdin.close()
        self.service_stdout.close()
        self.service.kill()
        self.service.wait()

    def expect_termination(self) -> int:
        try:
            return self.service.wait(2)
        except subprocess.TimeoutExpired:
            raise DidNotTerminate()

    def write(self, d: bytes) -> None:
        self.service_stdin.write(d)
        self.service_stdin.flush()

    def read_line(self) -> bytes:
        return self.service_stdout.readline()

    def test_000_bye(self) -> None:
        self.write(b"GETINFO version\n")
        self.assertRegex(self.read_line(), rb"\AD\s")
        self.assertRegex(self.read_line(), rb"\AOK\s")

        self.write(b"BYE\n")
        self.assertRegex(self.read_line(), rb"\AOK\s")

        self.expect_termination()

    def test_001_close(self) -> None:
        self.service_stdin.close()

        self.expect_termination()

    def test_002_filterd(self) -> None:
        self.write(b"GETINFO asdf\n")
        self.assertEqual(
            self.read_line(), b"ERR 67109888 Command filtered by split-gpg2.\n"
        )

        self.expect_termination()

    def test_003_agent_kill(self) -> None:
        self.write(b"GETINFO version\n")
        self.assertRegex(self.read_line(), rb"\AD\s")
        self.assertRegex(self.read_line(), rb"\AOK\s")

        # Simulate a sudden exit of gpg-agent. (Forcefully killing it is hard,
        # since gpg-agent doesn't like to be started in the foreground. So for
        # now ask it to terminate itself.)
        subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=self.test_env)

        # We currently don't detect a disconnected agent until we try to
        # communicate with it. So we have to trigger it.
        self.write(b"GETINFO version\n")

        self.expect_termination()

    def test_004_test_self_test(self) -> None:
        # Test out test method. With no reason to terminate it should still be
        # running.
        self.write(b"GETINFO version\n")
        self.assertRegex(self.read_line(), rb"\AD\s")
        self.assertRegex(self.read_line(), rb"\AOK\s")

        with self.assertRaises(DidNotTerminate):
            self.expect_termination()
