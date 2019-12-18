#!/usr/bin/python3
# split-gpg2.py
# Copyright (C) 2014 HW42 <hw42@ipsumj.de>
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
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Part of split-gpg2.
#
# This implements the server part. See README for details.


import asyncio
import enum

import logging
import os
import pathlib
import re
import signal
import socket
import string
import subprocess
import sys
import time
from typing import Optional, Dict, Callable, Awaitable, Tuple, Pattern

# from assuan.h
ASSUAN_LINELENGTH = 1002


class GPGErrorCode:
    # see gpg-error.h
    SOURCE_SHIFT = 24
    SOURCE_GPGAGENT = 4
    ERR_USER_1 = 1024
    ERR_ASS_UNKNOWN_CMD = 275

    UnknownIPCCommand = SOURCE_GPGAGENT << SOURCE_SHIFT | ERR_ASS_UNKNOWN_CMD


class StartFailed(Exception):
    pass


class GetSocketPathFailed(Exception):
    pass


class ProtocolError(Exception):
    pass


class Filtered(Exception):
    gpg_message = "Command filtered by split-gpg2."
    code = (GPGErrorCode.SOURCE_GPGAGENT << GPGErrorCode.SOURCE_SHIFT |
            GPGErrorCode.ERR_USER_1)


@enum.unique
class OptionHandlingType(enum.Enum):
    fake = 1
    verify = 2
    override = 3


class HashAlgo:
    def __init__(self, name: str, lenght: int) -> None:
        self.name = name
        self.len = lenght


@enum.unique
class ServerState(enum.Enum):
    client_command = 1  # waiting for client command
    client_inquire = 2  # waiting for client response for inquire
    agent_response = 3  # waiting for agent response


def extract_args(untrusted_line: bytes, sep: bytes = b' '):
    """Split a line into a command and arguments (if any).

    Returns: tuple(untrusted_cmd, untrusted_args)
    """
    if sep in untrusted_line:
        return untrusted_line.split(sep, 1)
    return untrusted_line, None


class GpgServer:
    """
    Protocol class for interacting with remote client connecting to split-gpg2.
    This class contains methods that handle, sanitize, and pass down gpg
    agent protocol messages received from the client. This is also a
    central place keeping the state of given connection.

    Separate protocol (:py:class:`AgentProtocol`) is used to interact with
    local real gpg agent. Its instance is saved in *agent_protocol* attribute.
    """
    # pylint: disable=too-many-instance-attributes,too-many-public-methods
    # type hints, enable when python >= 3.6 will be everywhere...
    # inquire_commands: Dict[bytes, Callable[[bytes], Awaitable]]
    # timer_delay: Dict[str, Optional[int]]
    # hash_algos: Dict[int, HashAlgo]
    # options: Dict[bytes, Tuple[OptionHandlingType, bytes]]
    # commands: Dict[bytes, Callable[[bytes], Awaitable]]
    # client_domain: str

    cache_nonce_regex = re.compile(rb'\A[0-9A-F]{24}\Z')

    def __init__(self, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter, client_domain: str):

        # configuration options:
        self.verbose_notifications = False
        self.timer_delay = self.default_timer_delay()
        #: allow client to generate a new key
        self.allow_keygen = False
        #: signal those Futures when connection is terminated
        self.notify_on_disconnect = set()
        self.log_io_enable = False

        self.client_reader = reader
        self.client_writer = writer
        self.client_domain = client_domain
        self.commands = self.default_commands()
        self.options = self.default_options()
        self.hash_algos = self.default_hash_algos()

        self.log = logging.getLogger('splitgpg2.Server')
        self.agent_socket_path = None
        self.agent_reader = None
        self.agent_writer = None
        self.untrusted_input_buffer = bytearray()

        debug_log = os.environ.get('QUBES_SPLIT_GPG2_DEBUG_LOG', None)
        if debug_log:
            handler = logging.FileHandler(debug_log)
            self.log.addHandler(handler)
            self.log.setLevel(logging.DEBUG)
            self.log_io_enable = True

    async def run(self):
        await self.connect_agent()
        try:
            while not self.client_reader.at_eof():
                await self.handle_command()
        finally:
            # close connection to the real gpg agent too
            self.agent_writer.close()

    def log_io(self, prefix, untrusted_msg):
        if not self.log_io_enable:
            return
        allowed = string.printable.\
            replace('\n', '').\
            replace('\r', '').\
            replace('\f', '').\
            replace('\v', '')
        allowed = allowed.encode('ascii')
        self.log.warning('%s: %s', prefix, ''.join(
            chr(c) if c in allowed else '.'
            for c in untrusted_msg.strip()))

    async def connect_agent(self):
        try:
            subprocess.check_call(['gpgconf', '--launch', 'gpg-agent'])
        except subprocess.CalledProcessError:
            raise StartFailed

        dirs = subprocess.check_output(['gpgconf', '--list-dirs'])
        # search for agent-socket:/run/user/1000/gnupg/S.gpg-agent
        agent_socket_path = [d.split(b':', 1)[1] for d in dirs.splitlines()
                             if d.startswith(b'agent-socket:')][0]
        self.agent_socket_path = agent_socket_path.decode()

        self.agent_reader, self.agent_writer = await asyncio.open_unix_connection(
                path=self.agent_socket_path)

        if self.verbose_notifications:
            self.notify('connected')

        # wait for agent hello
        await self.handle_agent_response()

    def abort(self, reason):
        self.log.error('%s; Aborting!', reason)
        self.client_writer.close()
        self.agent_writer.close()

    def abort_on_filtered_error(self, e):
        self.notify('command filtered out')
        self.client_write('ERR {} {}\n'.format(e.code, e.gpg_message).encode())
        # break handling since we aren't sure that clients handle the error
        # correctly. This makes the filtering easier to implement and
        # we ensure that a client does not wrongly assumes that a command
        # was successful while is was indeed filtered out.
        self.abort('command filtered out')

    async def handle_command(self):
        untrusted_line = await self.read_one_line_from_client()
        if not untrusted_line:
            # EOF
            return
        try:
            untrusted_cmd, untrusted_args = extract_args(untrusted_line)
            try:
                command = self.commands[untrusted_cmd]
            except KeyError:
                raise Filtered
            await command(untrusted_args=untrusted_args)
        except Filtered as e:
            self.log.exception(e)
            self.abort_on_filtered_error(e)
        except:  # pylint: disable=bare-except
            self.log.exception('Error processing command')
            self.abort('error')

    async def handle_inquire(self, inquire_commands):
        untrusted_line = await self.read_one_line_from_client()
        try:
            untrusted_cmd, untrusted_args = extract_args(untrusted_line)
            try:
                inquire_command = inquire_commands[untrusted_cmd]
            except KeyError:
                raise Filtered
            return await inquire_command(untrusted_args=untrusted_args)
        except Filtered as e:
            self.abort_on_filtered_error(e)
        except:  # pylint: disable=bare-except
            self.log.exception('Error processing inquire')
            self.abort('error')

    def default_commands(self):
        return {
            b'RESET': self.command_RESET,
            b'OPTION': self.command_OPTION,
            b'AGENT_ID': self.command_AGENT_ID,
            b'HAVEKEY': self.command_HAVEKEY,
            b'KEYINFO': self.command_KEYINFO,
            b'GENKEY': self.command_GENKEY,
            b'SIGKEY': self.command_SIGKEY,
            b'SETKEY': self.command_SETKEY,
            b'SETKEYDESC': self.command_SETKEYDESC,
            b'PKDECRYPT': self.command_PKDECRYPT,
            b'SETHASH': self.command_SETHASH,
            b'PKSIGN': self.command_PKSIGN,
            b'GETINFO': self.command_GETINFO,
            b'BYE': self.command_BYE
        }

    @staticmethod
    def default_options():
        return {
            # should be overriden on startup to reflect sensible values
            b'ttyname': (OptionHandlingType.fake, b'OK'),
            b'ttytype': (OptionHandlingType.fake, b'OK'),
            b'display': (OptionHandlingType.override, b':0'),
            b'lc-ctype': (OptionHandlingType.fake, b'OK'),
            b'lc-messages': (OptionHandlingType.fake, b'OK'),
            b'putenv': (OptionHandlingType.fake, b'OK'),
            b'allow-pinentry-notify': (OptionHandlingType.verify, None),
            b'agent-awareness': (OptionHandlingType.verify, b'2.1.0')
        }

    @staticmethod
    def default_timer_delay():
        return {
            'PKSIGN': None,     # always query for signing
            'PKDECRYPT': 300    # 5 min
        }

    @staticmethod
    def default_hash_algos():
        return {
            2: HashAlgo('sha1', 40),
            3: HashAlgo('rmd160', 40),
            8: HashAlgo('sha256', 64),
            9: HashAlgo('sha384', 96),
            10: HashAlgo('sha512', 128),
            11: HashAlgo('sha224', 56),
        }

    @staticmethod
    def notify(msg):
        # TODO: call into dbus directly
        subprocess.call(['notify-send', 'split-gpg2: {}'.format(msg)])

    def request_timer(self, name):
        now = time.time()
        delay = self.timer_delay[name]
        timestamp_path = self.timestamp_path(name)
        if delay is not None:
            try:
                mtime = timestamp_path.stat().st_mtime
                if mtime + delay > now:
                    self.notify('command {} automatically allowed'.format(name))
                    return
            except FileNotFoundError:
                pass

        short_msg = "split-gpg2: '{}' wants to execute {}".format(
            self.client_domain, name)
        question = '{}\nDo you want to allow this{}?'.format(
            short_msg,
            'for the next {}s'.format(delay) if delay is not None else '')
        if subprocess.call(['zenity', '--question', '--title', short_msg,
                            '--text', question]) != 0:
            raise Filtered

        self.notify('command {} allowed'.format(name))
        timestamp_path.touch()

    def timestamp_path(self, name) -> pathlib.Path:
        return pathlib.Path('{}_qubes-split-gpg2-timestamp_{}'.format(
            self.agent_socket_path, name))

    def client_write(self, data):
        self.log_io('C <<<', data)
        self.client_writer.write(data)

    async def read_one_line_from_client(self):
        untrusted_line = await self.client_reader.readline()
        untrusted_line = untrusted_line.rstrip(b'\n')
        # pylint: disable=arguments-differ
        if len(untrusted_line) > ASSUAN_LINELENGTH:
            self.log.error('Line too long, dropping')
            return b''
        self.log_io('C >>>', untrusted_line)
        return untrusted_line

    async def send_inquire(self, inquire, inquire_commands):
        self.client_write(b'INQUIRE ' + inquire + b'\n')
        while True:
            if not await self.handle_inquire(inquire_commands):
                break

    def fake_respond(self, response):
        self.client_write(response + b'\n')

    @staticmethod
    def verify_keygrip_arguments(min_count, max_count, untrusted_args):
        args_regex = re.compile(rb'\A[0-9A-F]{40}( [0-9A-F]{40}){%d,%d}\Z' %
                                (min_count-1, max_count-1))

        if args_regex.match(untrusted_args) is None:
            raise Filtered
        return untrusted_args

    def sanitize_key_desc(self, untrusted_args: bytes) -> bytes:
        untrusted_args = untrusted_args.replace(b'+', b' ')
        untrusted_args = re.sub(
            rb'%[0-9A-F]{2}',
            lambda m: bytes([int(m.group(0)[1:].decode('ascii'), 16)]),
            untrusted_args
        )
        allowed_ascii = list(range(0x20, 0x7e)) + [0x0a]
        args = "Message from '{}':\n{}".format(
            self.client_domain,
            ''.join((chr(c) if c in allowed_ascii else '.')
                    for c in untrusted_args)
        )
        return args.replace('%', '%25').\
            replace('+', '%2B').\
            replace('\n', '%0A').\
            replace(' ', '+').\
            encode('ascii')

    async def command_RESET(self, untrusted_args: Optional[bytes]):
        if untrusted_args is not None:
            raise Filtered
        await self.send_agent_command(b'RESET', None)

    async def command_OPTION(self, untrusted_args: Optional[bytes]):
        if not untrusted_args:
            raise Filtered

        untrusted_name, untrusted_value = extract_args(untrusted_args, b'=')
        try:
            action, opts = self.options[untrusted_name]
            name = untrusted_name
        except KeyError:
            raise Filtered

        if action == OptionHandlingType.override:
            if opts is not None:
                option_arg = b'%s=%s' % (name, opts)
            else:
                option_arg = name
        elif action == OptionHandlingType.verify:
            if callable(opts):
                verified = opts(untrusted_value=untrusted_value)
            elif isinstance(opts, Pattern):
                verified = (opts.match(untrusted_value) is not None)
            else:
                verified = (untrusted_value == opts)
            if not verified:
                raise Filtered
            value = untrusted_value

            if value is not None:
                option_arg = b'%s=%s' % (name, value)
            else:
                option_arg = name

        elif action == OptionHandlingType.fake:
            self.fake_respond(opts)
            return

        else:
            raise Filtered

        await self.send_agent_command(b'OPTION', option_arg)

    async def command_AGENT_ID(self, untrusted_args: Optional[bytes]):
        # pylint: disable=unused-argument
        self.fake_respond(
            b'ERR %d unknown IPC command' % GPGErrorCode.UnknownIPCCommand)

    async def command_HAVEKEY(self, untrusted_args: Optional[bytes]):
        # upper keygrip limit is arbitary
        args = self.verify_keygrip_arguments(1, 200, untrusted_args)
        await self.send_agent_command(b'HAVEKEY', args)

    async def command_KEYINFO(self, untrusted_args: Optional[bytes]):
        args = self.verify_keygrip_arguments(1, 1, untrusted_args)
        await self.send_agent_command(b'KEYINFO', args)

    async def command_GENKEY(self, untrusted_args: Optional[bytes]):
        if not self.allow_keygen:
            raise Filtered
        args = []
        if untrusted_args is not None:
            cache_nonce_added = False
            for untrusted_arg in untrusted_args.split(b' '):
                if untrusted_args == b'--no-protection':
                    # according to documentation,
                    # possible options (all related to password):
                    # --inq-passwd
                    # --no-protection
                    # --preset
                    # allow only --no-protection
                    if cache_nonce_added:
                        # option must come before cache_nonce
                        raise Filtered
                    args.append(untrusted_args)
                elif untrusted_arg in (b'--inq-passwd', b'--preset'):
                    # ignore other password-related options - do not
                    # accept passphrase from the client
                    pass
                elif self.cache_nonce_regex.match(untrusted_arg) \
                        and not cache_nonce_added:
                    args.append(untrusted_arg)
                    cache_nonce_added = True
                else:
                    raise Filtered

        args = b' '.join(args)
        await self.send_agent_command(b'GENKEY', args)

    async def command_SIGKEY(self, untrusted_args: Optional[bytes]):
        args = self.verify_keygrip_arguments(1, 1, untrusted_args)
        await self.send_agent_command(b'SIGKEY', args)

    async def command_SETKEY(self, untrusted_args: Optional[bytes]):
        args = self.verify_keygrip_arguments(1, 1, untrusted_args)
        await self.send_agent_command(b'SETKEY', args)

    async def command_SETKEYDESC(self, untrusted_args: Optional[bytes]):
        # XXX: is there a better way than showing the message
        #      from the untrusted domain
        args = self.sanitize_key_desc(untrusted_args)
        await self.send_agent_command(b'SETKEYDESC', args)

    async def command_PKDECRYPT(self, untrusted_args: Optional[bytes]):
        if untrusted_args is not None:
            raise Filtered
        self.request_timer('PKDECRYPT')
        await self.send_agent_command(b'PKDECRYPT', None)

    async def command_SETHASH(self, untrusted_args: Optional[bytes]):
        untrusted_alg, untrusted_hash = untrusted_args.split(b' ', 1)
        try:
            alg = int(untrusted_alg)
            alg_param = self.hash_algos[alg]
        except (KeyError, ValueError):
            raise Filtered

        if not untrusted_hash:
            raise Filtered

        hash_regex = re.compile(rb'\A[0-9A-F]{%d}\Z' % alg_param.len)
        if hash_regex.match(untrusted_hash) is None:
            raise Filtered
        hash_value = untrusted_hash

        await self.send_agent_command(
            b'SETHASH', b'%d %s' % (alg, hash_value))

    async def command_PKSIGN(self, untrusted_args: Optional[bytes]):
        if untrusted_args is not None:
            if not untrusted_args.startswith(b'-- '):
                raise Filtered
            untrusted_args = untrusted_args[3:]
            if self.cache_nonce_regex.match(untrusted_args) is None:
                raise Filtered
            args = b'-- ' + untrusted_args
        else:
            args = None

        self.request_timer('PKSIGN')

        await self.send_agent_command(b'PKSIGN', args)

    async def command_GETINFO(self, untrusted_args: Optional[bytes]):
        if untrusted_args != b'version':
            raise Filtered
        args = untrusted_args

        await self.send_agent_command(b'GETINFO', args)

    async def command_BYE(self, untrusted_args: Optional[bytes]):
        if untrusted_args is not None:
            raise Filtered
        await self.send_agent_command(b'BYE', None)
        self.client_writer.close()

    def get_inquires_for_command(self, command: bytes) -> Dict[bytes, Callable]:
        if command == b'GENKEY':
            inquires = {
                b'KEYPARAM': self.inquire_KEYPARAM,
                b'PINENTRY_LAUNCHED': self.inquire_PINENTRY_LAUNCHED,
            }
            return inquires
        if command == b'PKDECRYPT':
            return {
                b'CIPHERTEXT': self.inquire_CIPHERTEXT,
                b'PINENTRY_LAUNCHED': self.inquire_PINENTRY_LAUNCHED,
            }
        if command == b'PKSIGN':
            return {
                b'PINENTRY_LAUNCHED': self.inquire_PINENTRY_LAUNCHED,
            }
        return {}

    async def send_agent_command(self, command: bytes, args: Optional[bytes]):
        """ Sends command to local gpg agent and handle the response """
        expected_inquires = self.get_inquires_for_command(command)
        if args:
            cmd_with_args = command + b' ' + args + b'\n'
        else:
            cmd_with_args = command + b'\n'
        self.agent_write(cmd_with_args)
        while True:
            more_expected = await self.handle_agent_response(
                    expected_inquires=expected_inquires)
            if not more_expected:
                break

    def agent_write(self, data):
        self.log_io('A <<<', data)
        self.agent_writer.write(data)

    async def handle_agent_response(self, expected_inquires=None):
        """ Receive and handle one agent response. Return whether there are
        more expected """
        if expected_inquires is None:
            expected_inquires = {}
        # We generally consider the agent as trusted. But since the client can
        # determine part of the response we handle this here as untrusted.
        untrusted_line = await self.agent_reader.readline()
        untrusted_line = untrusted_line.rstrip(b'\n')
        self.log_io('A >>>', untrusted_line)
        untrusted_res, untrusted_args = extract_args(untrusted_line)
        if untrusted_res in (b'D', b'S'):
            # passthrough to the client
            self.client_write(untrusted_line + b'\n')
            return True
        if untrusted_res in (b'OK', b'ERR'):
            # passthrough to the client and signal command complete
            self.client_write(untrusted_line + b'\n')
            return False
        if untrusted_res == b'INQUIRE':
            if not untrusted_args:
                raise Filtered
            await self.handle_agent_inquire(
                    expected_inquires=expected_inquires,
                    untrusted_args=untrusted_args)
            return True
        raise ProtocolError('unexpected gpg-agent response')

    async def handle_agent_inquire(self, expected_inquires, *, untrusted_args):
        untrusted_inq, untrusted_inq_args = extract_args(untrusted_args)
        try:
            inquire = expected_inquires[untrusted_inq]
        except KeyError:
            raise Filtered
        await inquire(untrusted_args=untrusted_inq_args)

    # region INQUIRE commands sent from gpg-agent
    #

    async def inquire_KEYPARAM(self, untrusted_args):
        if untrusted_args is not None:
            self.abort('unexpected arguments to KEYPARAM inquire')
        await self.send_inquire(b'KEYPARAM', {
            b'D': self.inquire_command_D,
            b'END': self.inquire_command_END,
        })

    async def inquire_PINENTRY_LAUNCHED(self, untrusted_args):
        # This comes from the local agent and shouldn't be controlled by the
        # untrusted client. Additionally the only thing we do with it is to
        # send it back to the client.
        args = untrusted_args

        await self.send_inquire(b'PINENTRY_LAUNCHED ' + args, {
            b'END': self.inquire_command_END,
        })

    async def inquire_CIPHERTEXT(self, untrusted_args):
        if untrusted_args is not None:
            self.abort('unexpected arguments to CIPHERTEXT inquire')
        await self.send_inquire(b'CIPHERTEXT', {
            b'D': self.inquire_command_D,
            b'END': self.inquire_command_END,
        })

    # endregion

    # region INQUIRE responses sent by client back to the agent
    #
    # each function returns whether further responses are expected

    async def inquire_command_D(self, *, untrusted_args):
        # XXX: should we sanitize this here?
        self.agent_write(b'D ' + untrusted_args + b'\n')
        return True

    async def inquire_command_END(self, *, untrusted_args):
        if untrusted_args is not None:
            self.abort('unexpected arguments to END')
        self.agent_write(b'END\n')
        return False

    # endregion


TIMER_NAMES = {
    'QUBES_SPLIT_GPG2_PKSIGN_AUTOACCEPT_TIME': 'PKSIGN',
    'QUBES_SPLIT_GPG2_PKDECRYPT_AUTOACCEPT_TIME': 'PKDECRYPT',
}

def open_stdin_connection(*, loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()
    sock = socket.fromfd(sys.stdin.fileno(), socket.AF_UNIX, socket.SOCK_STREAM)
    reader = asyncio.StreamReader(loop=loop)
    protocol = asyncio.StreamReaderProtocol(reader, loop=loop)
    transport, _ = loop.run_until_complete(
        loop.connect_accepted_socket(
            lambda: protocol, sock))
    writer = asyncio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer

def main():
    # request bi-directional socket on stdin
    if 'QREXEC_AGENT_PID' in os.environ:
        os.kill(int(os.environ['QREXEC_AGENT_PID']), signal.SIGUSR1)

    client_domain = os.environ['QREXEC_REMOTE_DOMAIN']
    loop = asyncio.get_event_loop()
    reader, writer = open_stdin_connection()
    server = GpgServer(reader, writer, client_domain)

    for timer in TIMER_NAMES:
        if timer in os.environ:
            value = os.environ[timer]
            server.timer_delay[TIMER_NAMES[timer]] = int(value) if re.match(r'\A(0|[1-9][0-9]*)\Z', value) else None

    if os.environ.get('QUBES_SPLIT_GPG2_VERBOSE_NOTIFICATIONS', False) == 'yes':
        server.verbose_notifications = True

    connection_terminated = loop.create_future()
    server.notify_on_disconnect.add(connection_terminated)
    loop.run_until_complete(server.run())
