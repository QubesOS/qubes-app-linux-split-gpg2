#!/usr/bin/python3
#
# Copyright (C) 2019 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
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

import asyncio
import configparser
import functools
import os
import shutil
import subprocess
import tempfile
import unittest
import base64
import re
from unittest import TestCase
from unittest import mock
from . import GpgServer

class SimplePinentry(asyncio.Protocol):
    def __init__(self, cmd_mock) -> None:
        super().__init__()
        self.cmd_mock = cmd_mock


    def connection_made(self, transport) -> None:
        self.transport = transport
        self.transport.write(b'OK hello\n')

    def data_received(self, data: bytes) -> None:
        for command in data.split(b'\n'):
            if not command:
                continue
            self.cmd_mock(command)
            if command == b'GETPIN':
                self.transport.write(b'D password132\n')
            self.transport.write(b'OK\n')
            if command == b'BYE':
                self.transport.close()


class TC_Server(TestCase):
    key_uid = 'user@localhost'

    def setup_server(self, reader, writer):
        # tests assume certain responses - force specific locale
        os.environ['LC_ALL'] = 'C'
        gpg_server = GpgServer(reader, writer, 'testvm')
        # key generation tests - allow non-interactive operation
        if self.id().rsplit('.', 1)[-1] in ('test_001_genkey',
                                            'test_003_gen_and_list',
                                            'test_009_genkey_with_pinentry',
                                            'test_011_genkey_passphrase_empty',
                                            'test_012_genkey_passphrase_non_empty'):
            gpg_server.allow_keygen = True
        self.request_timer_mock = mock.patch.object(
            gpg_server, 'request_timer').start()
        self.notify_mock = mock.patch.object(
            gpg_server, 'notify').start()
        gpg_server.log_io_enable = True
        gpg_server.gnupghome = os.environ['GNUPGHOME']
        gpg_server.config_loaded = True
        asyncio.ensure_future(gpg_server.run())

    def start_dummy_pinentry(self):
        self.pinentry_command = mock.Mock()
        socket_path = self.gpg_dir.name + '/pinentry.sock'
        self.pinentry_server = self.loop.run_until_complete(
            self.loop.create_unix_server(
                lambda: SimplePinentry(self.pinentry_command), socket_path))

        wrapper_path = self.gpg_dir.name + '/pinentry-wrapper'
        with open(wrapper_path, 'w') as wrapper:
            wrapper.write('#!/bin/sh\n')
            wrapper.write('exec socat UNIX:{} STDIO\n'.format(socket_path))
        os.chmod(wrapper_path, 0o755)
        with open(self.gpg_dir.name + '/server/gpg-agent.conf', 'a') as conf:
            conf.write('pinentry-program {}\n'.format(wrapper_path))


    def setUp(self) -> None:
        super().setUp()

        self.counter = 0
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.gpg_dir = tempfile.TemporaryDirectory()
        # use separate GNUPGHOME for client and server, to force different
        # sockets
        self.test_environ = os.environ.copy()
        self.test_environ['GNUPGHOME'] = self.gpg_dir.name
        gpgconf_output = subprocess.check_output(
            ['gpgconf', '--list-dirs'],
            env=self.test_environ).decode()
        self.socket_path = [l.split(':', 1)[1]
                            for l in gpgconf_output.splitlines()
                            if l.startswith('agent-socket:')][0]
        # environment for the server and real gpg-agent
        os.environ['GNUPGHOME'] = self.gpg_dir.name + '/server'
        os.mkdir(os.environ['GNUPGHOME'], mode=0o700)

        self.server = self.loop.run_until_complete(
            asyncio.start_unix_server(self.setup_server,
                                      self.socket_path))

    def tearDown(self) -> None:
        try:
            self.pinentry_server.close()
            self.loop.run_until_complete(self.pinentry_server.wait_closed())
        except AttributeError:
            pass
        self.server.close()
        self.loop.run_until_complete(self.server.wait_closed())
        self.gpg_dir.cleanup()
        del os.environ['GNUPGHOME']
        mock.patch.stopall()
        super(TC_Server, self).tearDown()

    def genkey(self):
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--batch', '--passphrase', '', '--quick-gen-key',
            self.key_uid,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.skipTest('failed to generate key: {}{}'.format(
                stdout.decode(), stderr.decode()))
        # "export" public key to client keyring
        shutil.copy(self.gpg_dir.name + '/server/pubring.kbx',
                    self.gpg_dir.name + '/pubring.kbx')
        shutil.copy(self.gpg_dir.name + '/server/trustdb.gpg',
                    self.gpg_dir.name + '/trustdb.gpg')

    def test_000_handshake(self):
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg-connect-agent', '/bye', env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        stderr = stderr.replace(
            b'gpg-connect-agent: connection to the agent is in restricted mode\n',
            b'').replace(
            b'gpg-connect-agent: connection to agent is in restricted mode\n',
            b'')
        if p.returncode or stderr or stdout:
            self.fail('gpg-connect-agent exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))

    def generate_key(self, ty, subkey_ty, key_param, subkey_param, grip=None, *, subkey_usage='encrypt', client=True):
        fpr_re = re.compile(rb'\A[0-9A-F]{40}\Z')
        email = 'a' + str(self.counter) + self.key_uid
        self.counter += 1
        handle = base64.b64encode(os.urandom(32)).decode('ascii', 'strict')
        def v(p):
            return (('Length' if isinstance(p, int) else 'Curve')
                    if grip is None else 'Grip')
        keygen_params = f"""\
Key-Type: {ty}
Key-{v(key_param)}: {key_param if grip is None else grip[0].decode()}
Key-Usage: cert,sign
Handle: {handle}
Subkey-Type: {subkey_ty}
Subkey-{v(subkey_param)}: {subkey_param if grip is None else grip[1].decode()}
Subkey-Usage: {subkey_usage}
Name-Real: Joe Tester
Name-Email: {email}
Expire-Date: 0
%no-protection
%commit
"""
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--batch', '--status-fd=1', '--gen-key', '--expert',
            env=self.test_environ if client else os.environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE,
            stdin=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate(
            input=keygen_params.encode('ascii', 'strict')))
        if p.returncode:
            self.fail('gpg2 --gen-key exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))

        if client:
            self.request_timer_mock.assert_called_with('PKSIGN')
        assert stdout.endswith(b'\n')
        fpr = None
        for status_line in stdout[:-1].split(b'\n'):
            assert status_line.startswith(b'[GNUPG:] ')
            status_line = status_line[9:]
            if not status_line.startswith(b'KEY_CREATED '):
                continue
            self.assertIs(fpr, None)
            _, _, fpr, gpg_handle = status_line.split(b' ')
            self.assertEqual(handle.encode(), gpg_handle)
            self.assertTrue(fpr_re.match(fpr))
        self.assertIsNot(fpr, None)
        # "export" public key to server keyring
        if client:
            shutil.copy(self.gpg_dir.name + '/pubring.kbx',
                        self.gpg_dir.name + '/server/pubring.kbx')
            shutil.copy(self.gpg_dir.name + '/trustdb.gpg',
                        self.gpg_dir.name + '/server/trustdb.gpg')
            # verify the key is there bypassing splitgpg2, test one thing at
            # a time
            p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
                b'gpg', b'--with-colons', b'--with-keygrip', b'-K', b'0x' + fpr,
                stderr=subprocess.PIPE, stdout=subprocess.PIPE))
            stdout, stderr = self.loop.run_until_complete(p.communicate())
            if p.returncode:
                self.fail('generated key not found: {}{}'.format(
                    stdout.decode(), stderr.decode()))
            self.assertIn(b'sec:u:', stdout)
            self.assertIn(self.key_uid.encode('ascii', 'strict'), stdout)
            self.assertTrue(stdout.endswith(b'\n'))
        return (fpr, stdout)

    def test_001_genkey(self):
        fpr_re = re.compile(rb'\A[0-9A-F]{40}\Z')
        def do_test(ty, subkey_ty, key_param, subkey_param):
            with self.subTest(repr((ty, subkey_ty, key_param, subkey_param))):
                fpr, stdout = self.generate_key(ty, subkey_ty, key_param, subkey_param)
                keygrips = [None, None]
                for i in stdout[:-1].split(b'\n'):
                    if i.startswith(b'sec:'):
                        offset = 0
                    elif i.startswith(b'ssb:'):
                        offset = 1
                    elif i.startswith(b'grp:'):
                        keygrips[offset] = i.split(b':')[9]
                        self.assertTrue(fpr_re.match(keygrips[offset]))
                    elif offset == 0 and i.startswith(b'fpr:'):
                        # Check that the fingerprint is correct
                        self.assertEqual(fpr, i.split(b':')[9])
                self.assertIsNot(keygrips[0], None)
                self.assertIsNot(keygrips[1], None)
                fpr, stdout = self.generate_key(ty, subkey_ty, key_param, subkey_param, keygrips)
                for i in stdout[:-1].split(b'\n'):
                    if i.startswith(b'sec:'):
                        offset = 0
                    elif i.startswith(b'ssb:'):
                        offset = 1
                    elif i.startswith(b'grp:'):
                        # Check that the new key has the same keygrip
                        # that was used to generate it.
                        self.assertEqual(keygrips[offset], i.split(b':')[9])
                    elif offset == 0 and i.startswith(b'fpr:'):
                        # Check that the fingerprint is correct
                        self.assertEqual(fpr, i.split(b':')[9])

        config_args = ('gpg', '--with-colons', '--no-options', '--list-config',
                       '-o/dev/stdout', 'curve')
        output = subprocess.run(config_args,
                capture_output=True,
                check=True,
                stdin=subprocess.DEVNULL).stdout.decode('ascii', 'strict')
        assert output.startswith('cfg:curve:')
        curves = output[10:].strip().split(';')
        do_test('RSA', 'RSA', 2048, 2048)
        do_test('DSA', 'ELG', 2048, 2048)
        do_test('ECDSA', 'ECDH', 'NIST P-256', 'NIST P-256')
        do_test('ECDSA', 'ECDH', 'NIST P-384', 'NIST P-384')
        do_test('ECDSA', 'ECDH', 'NIST P-521', 'NIST P-521')
        do_test('ECDSA', 'ECDH', 'secp256k1', 'secp256k1')
        do_test('EDDSA', 'ECDH', 'Ed25519', 'Curve25519')

        for i in curves:
            if i.startswith('ed'):
                kex_version = 'cv' + i[2:]
                assert kex_version in curves, f'found {i} but not {kex_version}'
                do_test('EDDSA', 'ECDH', i, kex_version)
            elif i.startswith('cv'):
                assert 'ed' + i[2:] in curves, f'found {i} but not {"ed" + i[2:]}'
            else:
                if i.startswith('nistp'):
                    i = 'NIST P-' + i[5:]
                do_test('ECDSA', 'ECDH', i, i)

    def test_002_list_keys(self):
        self.genkey()

        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--with-colons', '-K', self.key_uid,
            env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.fail('generated key not found: {}{}'.format(
                stdout.decode(), stderr.decode()))
        self.assertIn(b'sec:u:', stdout)
        self.assertIn(self.key_uid.encode(), stdout)

    def test_003_gen_and_list(self):
        """Test automatic export after keygen"""
        keygen_params = """Key-Type: EdDSA
        Key-Curve: ed25519
        Name-Real: Joe Tester
        Name-Email: {}
        %no-protection
        %commit
        """.format(self.key_uid)
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--batch', '--gen-key',
            env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE,
            stdin=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate(
            input=keygen_params.encode()))
        if p.returncode:
            self.fail('gpg2 --quick-gen-key exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))

        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--with-colons', '-K', self.key_uid,
            env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.fail('generated key not found ({}): {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))
        self.assertIn(b'sec:u:', stdout)
        self.assertIn(self.key_uid.encode(), stdout)

    def test_004_sign(self):
        self.genkey()
        test_data = b'Data to sign'
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--local-user', self.key_uid, '--sign',
            '--output', self.gpg_dir.name + '/signed', '-',
            env=self.test_environ,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate(
            test_data))
        if p.returncode:
            self.fail('gpg2 --sign exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))

        # verify shouldn't need access to private key
        self.server.close()

        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--verify', self.gpg_dir.name + '/signed',
            env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.fail('gpg2 --sign exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))
        self.assertIn(b'gpg: Good signature from "%s"' % self.key_uid.encode(),
                      stderr)

    def test_005_decrypt(self):
        self.genkey()
        test_data = b'Data to encrypt'
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '-r', self.key_uid, '--encrypt',
            '--output', self.gpg_dir.name + '/encrypted', '-',
            env=self.test_environ,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate(
            test_data))
        if p.returncode:
            self.fail('gpg2 --sign exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))

        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--decrypt', self.gpg_dir.name + '/encrypted',
            env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.fail('gpg2 --sign exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))
        self.assertEqual(stdout, test_data)

    def test_006_sign_encrypt(self):
        self.genkey()
        test_data = b'Data to sign and encrypt'
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--local-user', self.key_uid, '--sign', '--encrypt',
            '-r', self.key_uid,
            '--output', self.gpg_dir.name + '/signed', '-',
            env=self.test_environ,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate(
            test_data))
        if p.returncode:
            self.fail('gpg2 --sign exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))

        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--output', '-',
            '--decrypt', self.gpg_dir.name + '/signed',
            env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.fail('gpg2 --sign exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))
        self.assertIn(b'gpg: Good signature from "%s"' % self.key_uid.encode(),
                      stderr)
        self.assertEqual(stdout, test_data)


    def test_007_sign_detached(self):
        self.genkey()
        test_data = b'Data to sign and encrypt'
        with open(self.gpg_dir.name + '/input_data', 'wb') as f_data:
            f_data.write(test_data)
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--local-user', self.key_uid, '--detach-sign',
            '--output', self.gpg_dir.name + '/signature',
            self.gpg_dir.name + '/input_data',
            env=self.test_environ,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate(
            test_data))
        if p.returncode:
            self.fail('gpg2 --sign exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))

        # verify shouldn't need access to private key
        self.server.close()

        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--verify', self.gpg_dir.name + '/signature',
            self.gpg_dir.name + '/input_data',
            env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.fail('gpg2 --sign exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))
        self.assertIn(b'gpg: Good signature from "%s"' % self.key_uid.encode(),
                      stderr)

    def test_008_export_secret_deny(self):
        self.genkey()
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '-a', '--export-secret-key', self.key_uid,
            env=self.test_environ,
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode == 0:
            self.fail('gpg2 --export-secret-key succeeded unexpectedly: {}{}'.format(
                stdout.decode(), stderr.decode()))

    @unittest.skip('pinentry setup is broken in CI')
    def test_009_genkey_with_pinentry(self):
        self.start_dummy_pinentry()
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--batch', '--quick-gen-key',
            self.key_uid,
            env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.fail('gpg2 --quick-gen-key exit with {}: {}{}'.format(
                p.returncode, stdout.decode(), stderr.decode()))

        self.pinentry_command.assert_any_call(b'GETPIN')

        self.request_timer_mock.assert_called_with('PKSIGN')

        # "export" public key to server keyring
        shutil.copy(self.gpg_dir.name + '/pubring.kbx',
                    self.gpg_dir.name + '/server/pubring.kbx')
        shutil.copy(self.gpg_dir.name + '/trustdb.gpg',
                    self.gpg_dir.name + '/server/trustdb.gpg')
        # verify the key is there bypassing splitgpg2, test one thing at a time
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--with-colons', '-K', self.key_uid,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.fail('generated key not found: {}{}'.format(
                stdout.decode(), stderr.decode()))
        self.assertIn(b'sec:u:', stdout)
        self.assertIn(self.key_uid.encode(), stdout)

    def test_010_genkey_deny(self):
        keygen_params = """Key-Type: EDDSA
Key-Curve: ed25519
Name-Real: Joe Tester
Name-Email: {}
%no-protection
%commit
""".format(self.key_uid)
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--batch', '--gen-key',
            env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE,
            stdin=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate(
            input=keygen_params.encode()))
        if p.returncode == 0:
            self.fail(
                'gpg2-agent did not refused to generate a key: {}{}'.format(
                stdout.decode(), stderr.decode()))

    def test_011_genkey_passphrase_empty(self):
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--batch', '--passphrase', '', '--quick-generate-key',
            '--default-new-key-alg=ed25519/cert,sign', '--',
            self.key_uid,
            env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE,
            stdin=subprocess.DEVNULL))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.fail('Key generation failed')
        # "export" public key to server keyring
        shutil.copy(self.gpg_dir.name + '/pubring.kbx',
                    self.gpg_dir.name + '/server/pubring.kbx')
        shutil.copy(self.gpg_dir.name + '/trustdb.gpg',
                    self.gpg_dir.name + '/server/trustdb.gpg')
        # verify the key is there bypassing splitgpg2, test one thing at a time
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--with-colons', '-K', self.key_uid,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.fail('generated key not found: {}{}'.format(
                stdout.decode(), stderr.decode()))
        self.assertIn(b'sec:u:', stdout)
        self.assertIn(self.key_uid.encode(), stdout)

    def test_012_genkey_passphrase_non_empty(self):
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--batch', '--passphrase', 'weak', '--quick-generate-key',
            '--default-new-key-alg=ed25519/cert,sign', '--',
            self.key_uid,
            env=self.test_environ,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE,
            stdin=subprocess.DEVNULL))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if not p.returncode:
            self.fail('Key generation did not fail')


class TC_Config(TestCase):
    key_uid = 'user@localhost'

    def setup_server(self, config, reader, writer):
        gpg_server = GpgServer(reader, writer, 'testvm')
        gpg_server.load_config(config['client:testvm'])
        self.request_timer_mock = mock.patch.object(
            gpg_server, 'request_timer').start()
        self.notify_mock = mock.patch.object(
            gpg_server, 'notify').start()
        gpg_server.log_io_enable = True
        asyncio.ensure_future(gpg_server.run())

    def setUp(self) -> None:
        super().setUp()

        # tests assume certain responses - force specific locale
        os.environ['LC_ALL'] = 'C'
        self.loop = asyncio.get_event_loop()
        self.gpg_dir = tempfile.TemporaryDirectory()
        # use separate GNUPGHOME for client and server, to force different
        # sockets
        self.test_environ = os.environ.copy()
        self.test_environ['GNUPGHOME'] = self.gpg_dir.name
        gpgconf_output = subprocess.check_output(
            ['gpgconf', '--list-dirs'],
            env=self.test_environ).decode()
        self.socket_path = [l.split(':', 1)[1]
                            for l in gpgconf_output.splitlines()
                            if l.startswith('agent-socket:')][0]
        self.server_gpghome = self.gpg_dir.name + '/server'
        os.mkdir(self.server_gpghome, mode=0o700)


    def tearDown(self) -> None:
        try:
            self.server.close()
            self.loop.run_until_complete(self.server.wait_closed())
        except AttributeError:
            pass
        self.gpg_dir.cleanup()
        mock.patch.stopall()
        super().tearDown()

    def genkey(self):
        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--homedir', self.server_gpghome,
            '--batch', '--passphrase', '', '--quick-gen-key',
            self.key_uid,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.skipTest('failed to generate key: {}{}'.format(
                stdout.decode(), stderr.decode()))
        # "export" public key to client keyring
        shutil.copy(self.gpg_dir.name + '/server/pubring.kbx',
                    self.gpg_dir.name + '/pubring.kbx')
        shutil.copy(self.gpg_dir.name + '/server/trustdb.gpg',
                    self.gpg_dir.name + '/trustdb.gpg')

    def test_000_basic(self):
        reader = mock.Mock()
        writer = mock.Mock()
        config = configparser.ConfigParser()
        # configparser allows indented options
        config.read_string(
            f"""
            [DEFAULT]
            gnupghome = {self.server_gpghome}
            [client:testvm]
            autoaccept = yes
            pksign_autoaccept = 300
            verbose_notifications = yes
            allow_keygen = yes
            """)
        gpg_server = GpgServer(reader, writer, 'testvm')
        gpg_server.load_config(config['client:testvm'])
        self.assertTrue(gpg_server.allow_keygen)
        self.assertTrue(gpg_server.verbose_notifications)
        self.assertEqual(gpg_server.gnupghome, self.server_gpghome + '/qubes-auto-keyring')
        self.assertEqual(gpg_server.timer_delay['PKSIGN'], 300)
        self.assertEqual(gpg_server.timer_delay['PKDECRYPT'], -1)

    def test_001_per_client_gpghome(self):
        reader = mock.Mock()
        writer = mock.Mock()
        config = configparser.ConfigParser()
        # configparser allows indented options
        config.read_string(
            f"""
            [DEFAULT]
            isolated_gnupghome_dirs = {self.gpg_dir.name}
            """)
        gpg_server = GpgServer(reader, writer, 'server')
        gpg_server.load_config(config['DEFAULT'])
        self.assertEqual(gpg_server.gnupghome, self.server_gpghome + '/qubes-auto-keyring')

    def test_002_invalid(self):
        reader = mock.Mock()
        writer = mock.Mock()
        gpg_server = GpgServer(reader, writer, 'server')
        with self.assertRaises(ValueError):
            config = configparser.ConfigParser()
            config.read_string("""[DEFAULT]
            autoaccept = False
            """)
            gpg_server.load_config(config['DEFAULT'])
        with self.assertRaises(ValueError):
            config = configparser.ConfigParser()
            config.read_string("""[DEFAULT]
            pkdecrypt_autoaccept = -1
            """)
            gpg_server.load_config(config['DEFAULT'])
        with self.assertRaises(ValueError):
            config = configparser.ConfigParser()
            config.read_string("""[DEFAULT]
            allow_keygen = 7
            """)
            gpg_server.load_config(config['DEFAULT'])

    def test_003_option_typo(self):
        reader = mock.Mock()
        writer = mock.Mock()
        gpg_server = GpgServer(reader, writer, 'server')
        gpg_server.log = mock.Mock()
        config = configparser.ConfigParser()
        config.read_string("""[DEFAULT]
        autoaccept = no
        no_such_option = 1
        """)
        gpg_server.load_config(config['DEFAULT'])
        # warns about unsupported option only
        self.assertEquals(gpg_server.log.mock_calls, [
            mock.call.warning('Unsupported config option: %s', 'no_such_option'),
            mock.call.info('Using GnuPG home directory %s',
                           gpg_server.gnupghome[:-len('/qubes-auto-keyring')]),
        ])

    def test_010_gpghome(self):
        self.genkey()

        config = configparser.ConfigParser()
        # configparser allows indented options
        config.read_string(
            f"""
            [DEFAULT]
            gnupghome = {self.server_gpghome}
            [client:testvm]
            """)
        self.server = self.loop.run_until_complete(
            asyncio.start_unix_server(
                functools.partial(self.setup_server, config),
                self.socket_path))

        p = self.loop.run_until_complete(asyncio.create_subprocess_exec(
            'gpg', '--with-colons', f'--homedir={self.server_gpghome}',
            '-K', '--', self.key_uid,
            stderr=subprocess.PIPE, stdout=subprocess.PIPE))
        stdout, stderr = self.loop.run_until_complete(p.communicate())
        if p.returncode:
            self.fail('generated key not found: {}{}'.format(
                stdout.decode(), stderr.decode()))
        self.assertIn(b'sec:u:', stdout)
        self.assertIn(self.key_uid.encode(), stdout)
