# -*- coding: utf-8 -*-
#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2016 Marek Marczykowski-Górecki
#                               <marmarek@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
# USA.
#
import unittest

import qubes.tests.extra


class SplitGPGBase(qubes.tests.extra.ExtraTestCase):
    def setUp(self):
        super(SplitGPGBase, self).setUp()
        self.enable_network()
        self.backend, self.frontend = self.create_vms(["backend", "frontend"])

        self.backend.start()
        if self.backend.run('ls /etc/qubes-rpc/qubes.Gpg2', wait=True) != 0:
            self.skipTest('gpg-split2 not installed')
        # Whonix desynchronize time on purpose, so make sure the key is
        # generated in the past even when the frontend have clock few minutes
        #  into the future - otherwise new key may look as
        # generated in the future and be considered not yet valid
        if 'whonix' in self.template:
            self.backend.run("date -s -10min", user="root", wait=True)
        p = self.backend.run('mkdir -p -m 0700 .gnupg; gpg2 --gen-key --batch',
            passio_popen=True,
            passio_stderr=True)
        stdout, stderr = p.communicate('''
Key-Type: RSA
Key-Length: 1024
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 1024
Subkey-Usage: encrypt
Name-Real: Qubes test
Name-Email: user@localhost
Expire-Date: 0
%no-protection
%commit
        '''.encode())
        if p.returncode == 127:
            self.skipTest('gpg2 not installed')
        elif p.returncode != 0:
            self.fail('key generation failed: {}{}'.format(stdout, stderr))

        cmd = 'gpg2 --with-colons --list-key user@localhost'
        p = self.backend.run(cmd, passio_popen=True, passio_stderr=True)
        (stdout, stderr) = p.communicate()
        self.assertEqual(p.returncode, 0,
            '{} failed: {}{}'.format(cmd, stdout.decode(), stderr.decode()))
        fpr = [l for l in stdout.splitlines() if l.startswith(b'fpr:')][0]
        fpr = fpr.decode().split(":")[9]
        # add signing subkey
        p = self.backend.run(
            f"gpg2 --batch --passphrase "" --quick-add-key "
            f"{fpr} rsa sign never",
            passio_popen=True,
            passio_stderr=True)
        stdout, stderr = p.communicate()
        if p.returncode != 0:
            self.fail('subkey generation failed: {}{}'.format(
                      stdout, stderr))
        if 'whonix' in self.template:
            self.backend.run("date -s +10min", user="root", wait=True)

        p = self.backend.run('mkdir -p .config/qubes-split-gpg2; cat > .config/qubes-split-gpg2/qubes-split-gpg2.conf', passio_popen=True)
        p.communicate(
                b'[DEFAULT]\n'
                b'autoaccept = yes\n'
                )

        self.frontend.features['service.split-gpg2-client'] = True

        self.frontend.start()

        self.qrexec_policy('qubes.Gpg2', self.frontend.name, '@default',
            target=self.backend.name)

        # import public key to the frontend domain
        cmd = 'gpg2 -a --export user@localhost'
        p = self.backend.run(cmd, passio_popen=True, passio_stderr=True)
        (pubkey, stderr) = p.communicate()
        self.assertEqual(p.returncode, 0,
            '{} failed: {}'.format(cmd, stderr.decode()))
        cmd = 'gpg2 --import'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        (stdout, stderr) = p.communicate(pubkey)
        self.assertEqual(p.returncode, 0,
            '{} failed: {}{}'.format(cmd, stdout.decode(), stderr.decode()))
        # and set as trusted
        cmd = 'gpg2 --with-colons --list-key user@localhost'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        (stdout, stderr) = p.communicate()
        self.assertEqual(p.returncode, 0,
            '{} failed: {}{}'.format(cmd, stdout.decode(), stderr.decode()))
        fpr = [l for l in stdout.splitlines() if l.startswith(b'fpr:')][0]
        cmd = 'gpg2 --with-colons --import-ownertrust'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        (stdout, stderr) = p.communicate(
            fpr.replace(b'fpr:::::::::', b'') + b'6:\n')
        self.assertEqual(p.returncode, 0,
            '{} failed: {}{}'.format(cmd, stdout.decode(), stderr.decode()))


class TC_00_Direct(SplitGPGBase):
    def test_000_version(self):
        cmd = 'gpg2 --version'
        p = self.frontend.run(cmd, wait=True)
        self.assertEqual(p, 0, '{} failed'.format(cmd))

    def test_010_list_keys(self):
        cmd = 'gpg2 --list-keys'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        (keys, stderr) = p.communicate()
        self.assertEqual(p.returncode, 0,
            '{} failed: {}'.format(cmd, stderr.decode()))
        self.assertIn("Qubes test", keys.decode())
        cmd = 'gpg2 --list-secret-keys'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        (keys, stderr) = p.communicate()
        self.assertEqual(p.returncode, 0,
            '{} failed: {}'.format(cmd, stderr.decode()))
        self.assertIn("Qubes test", keys.decode())

    def test_020_export_secret_key_deny(self):
        # TODO check if backend really deny such operation, here it is denied
        # by the frontend
        cmd = 'gpg2 -a --export-secret-keys user@localhost'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        keys, stderr = p.communicate()
        self.assertNotEqual(p.returncode, 0,
            '{} succeeded unexpectedly: {}'.format(cmd, stderr.decode()))
        self.assertEqual(keys.decode(), '')

    def test_030_sign_verify(self):
        msg = "Test message"
        cmd = 'gpg2 -a --sign -u user@localhost'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        (signature, stderr) = p.communicate(msg.encode())
        self.assertEqual(p.returncode, 0,
            '{} failed: {}'.format(cmd, stderr.decode()))
        self.assertNotEqual('', signature.decode())

        cmd = "gpg2"
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        decoded_msg, verification_result = p.communicate(signature)
        self.assertEqual(p.returncode, 0,
            '{} failed: {}'.format(cmd, verification_result.decode()))
        self.assertEqual(decoded_msg.decode(), msg)
        self.assertIn('\ngpg: Good signature from', verification_result.decode())

    def test_031_sign_verify_detached(self):
        msg = "Test message"
        self.frontend.run('echo "{}" > message'.format(msg), wait=True)
        cmd = 'gpg2 --output=signature.asc -a -b --sign -u user@localhost message'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        stdout, stderr = p.communicate()
        self.assertEqual(p.returncode, 0,
            '{} failed: {}'.format(cmd, stderr.decode()))

        cmd = 'gpg2 --verify signature.asc message'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        decoded_msg, verification_result = p.communicate()
        self.assertEqual(p.returncode, 0,
            '{} failed: {}'.format(cmd, verification_result.decode()))
        self.assertEqual(decoded_msg.decode(), '')
        self.assertIn('\ngpg: Good signature from', verification_result.decode())

        # break the message and check again
        self.frontend.run('echo "{}" >> message'.format(msg), wait=True)
        cmd = 'gpg2 --verify signature.asc message'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        decoded_msg, verification_result = p.communicate()
        self.assertNotEqual(p.returncode, 0,
            '{} unexpecedly succeeded: {}'.format(cmd, verification_result.decode()))
        self.assertEqual(decoded_msg.decode(), '')
        self.assertIn('\ngpg: BAD signature from', verification_result.decode())

    def test_040_encrypt_decrypt(self):
        msg = "Test message"
        cmd = 'gpg2 --trust-model tofu -a --encrypt -r user@localhost'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        (encrypted, stderr) = p.communicate(msg.encode())
        self.assertEqual(p.returncode, 0,
            '{} failed: {}'.format(cmd, stderr.decode()))
        self.assertNotEqual('', encrypted.decode())

        cmd = "gpg2 --decrypt"
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        decoded_msg, stderr = p.communicate(encrypted)
        self.assertEqual(p.returncode, 0,
            '{} failed: {}'.format(cmd, stderr.decode()))
        self.assertEqual(decoded_msg.decode(), msg)

    def test_041_sign_encrypt_decrypt(self):
        msg = "Test message"
        cmd = 'gpg2 --trust-model tofu -a --sign --encrypt -u user@localhost -r user@localhost'
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        (encrypted, stderr) = p.communicate(msg.encode())
        self.assertEqual(p.returncode, 0,
            '{} failed: {}'.format(cmd, stderr.decode()))
        self.assertNotEqual('', encrypted.decode())

        cmd = "gpg2 --decrypt"
        p = self.frontend.run(cmd, passio_popen=True, passio_stderr=True)
        decoded_msg, verification_result = p.communicate(encrypted)
        self.assertEqual(p.returncode, 0,
            '{} failed: {}'.format(cmd, verification_result.decode()))
        self.assertEqual(decoded_msg.decode(), msg)
        self.assertIn('\ngpg: Good signature from', verification_result.decode())

    def test_050_generate(self):
        p = self.backend.run('cat >> .config/qubes-split-gpg2/qubes-split-gpg2.conf', passio_popen=True)
        p.communicate(b'allow_keygen = yes\n')

        # see comment in setUp()
        if 'whonix' in self.template:
            self.frontend.run("date -s -10min", user="root", wait=True)

        p = self.frontend.run('mkdir -p -m 0700 .gnupg; gpg2 --gen-key --batch',
                passio_popen=True)
        p.communicate('''
Key-Type: RSA
Key-Length: 1024
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 1024
Subkey-Usage: encrypt
Name-Real: Qubes test2
Name-Email: user2@localhost
Expire-Date: 0
%no-protection
%commit
        '''.encode())
        assert p.returncode == 0, 'key generation failed'
        # see comment in setUp()
        if 'whonix' in self.template:
            self.frontend.run("date -s +10min", user="root", wait=True)

        p = self.frontend.run('gpg2 --list-keys',
            passio_popen=True)
        (key_list, _) = p.communicate()
        self.assertIn('user2@localhost', key_list.decode())
        p = self.frontend.run('gpg2 --list-secret-keys',
            passio_popen=True)
        (key_list, _) = p.communicate()
        self.assertIn('user2@localhost', key_list.decode())

    def test_060_import_secret(self):
        # see comment in setUp()
        if 'whonix' in self.template:
            self.frontend.run("date -s -10min", user="root", wait=True)
        p = self.frontend.run('mkdir -p -m 0700 temp-gnupg; export GNUPGHOME=$HOME/temp-gnupg; '
                'gpgconf --launch gpg-agent && '
                'gpg2 --gen-key --batch && '
                'gpg2 -a --export-secret-key user2@localhost && '
                'gpgconf --kill gpg-agent',
                passio_popen=True)
        stdout, stderr = p.communicate('''
Key-Type: RSA
Key-Length: 1024
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 1024
Subkey-Usage: encrypt
Name-Real: Qubes test2
Name-Email: user2@localhost
Expire-Date: 0
%no-protection
%commit
        '''.encode())
        assert p.returncode == 0, 'key generation failed'
        # see comment in setUp()
        if 'whonix' in self.template:
            self.frontend.run("date -s +10min", user="root", wait=True)

        p = self.frontend.run('gpg2 --list-keys',
            passio_popen=True)
        (key_list, _) = p.communicate()
        self.assertNotIn('user2@localhost', key_list.decode())
        p = self.frontend.run('gpg2 --list-secret-keys',
            passio_popen=True)
        (key_list, _) = p.communicate()
        self.assertNotIn('user2@localhost', key_list.decode())

        p = self.frontend.run('gpg2 --import',
            passio_popen=True)
        p.communicate(stdout)
        # secret key import should be refused
        self.assertNotEqual(p.returncode, 0)

        p = self.frontend.run('gpg2 --list-keys',
            passio_popen=True)
        (key_list, _) = p.communicate()
        self.assertIn('user2@localhost', key_list.decode())
        p = self.frontend.run('gpg2 --list-secret-keys',
            passio_popen=True)
        (key_list, _) = p.communicate()
        self.assertNotIn('user2@localhost', key_list.decode())


class TC_10_Thunderbird(SplitGPGBase):

    scriptpath = '/usr/share/split-gpg2-tests/test_thunderbird.py'

    def setUp(self):
        if self.template.startswith('whonix-gw'):
            self.skipTest('whonix-gw template not supported by this test')
        super(TC_10_Thunderbird, self).setUp()
        self.frontend.run_service('qubes.WaitForSession', wait=True,
            input='user')
        if self.frontend.run('which thunderbird', wait=True) == 0:
            self.tb_name = 'thunderbird'
        elif self.frontend.run('which icedove', wait=True) == 0:
            self.tb_name = 'icedove'
        else:
            self.skipTest('Thunderbird not installed')
        # use dogtail 0.9.10 directly from git, until 0.9.10 gets packaged in
        # relevant distros; 0.9.9 have problems with handling unicode
        p = self.frontend.run(
                'git clone -n https://gitlab.com/dogtail/dogtail.git && '
                'cd dogtail && '
                'git checkout 4d7923dcda92c2c44309d2a56b0bb616a1855155',
                passio_popen=True, passio_stderr=True)
        stdout, stderr = p.communicate()
        if p.returncode:
            self.skipTest(
                'dogtail installation failed: {}{}'.format(stdout, stderr))

        # if self.frontend.run(
        #         'python -c \'import dogtail,sys;'
        #         'sys.exit(dogtail.__version__ < "0.9.0")\'', wait=True) \
        #         != 0:
        #     self.skipTest('dogtail >= 0.9.0 testing framework not installed')

        p = self.frontend.run('gsettings set org.gnome.desktop.interface '
                              'toolkit-accessibility true', wait=True)
        assert p == 0, 'Failed to enable accessibility toolkit'
        if self.frontend.run(
                'ls {}'.format(self.scriptpath), wait=True):
            self.skipTest('split-gpg2-tests package not installed')

        # run as root to not deal with /var/mail permission issues
        self.frontend.run(
            'mkdir -p Mail/new Mail/cur Mail/tmp',
            wait=True)

        # SMTP configuration
        self.smtp_server = self.frontend.run(
            'aiosmtpd -n -c aiosmtpd.handlers.Mailbox /home/user/Mail',
            passio_popen=True)

        # IMAP configuration
        self.imap_pw = "pass"
        if self.frontend.run("grep -rq mail_driver /etc/dovecot/", wait=True) == 0:
            self.frontend.run(
                'echo "mail_driver = maildir\nmail_path = ~/Mail\nmail_inbox_path = ~/Mail\nuserdb static {\n driver = passwd\n}\npassdb static {\n driver = static\n password=pass\n}" |\
                    tee /etc/dovecot/conf.d/100-mail.conf', wait=True, user="root")
        else:
            self.frontend.run(
                'echo "mail_location=maildir:~/Mail\nuserdb {\n driver = passwd\n}\npassdb $db_name {\n driver = static\n args = password=pass\n}" |\
                    tee /etc/dovecot/conf.d/100-mail.conf', wait=True, user="root")
        self.frontend.run(
            "sed -i 's/^!include/#\\0/' /etc/dovecot/conf.d/10-auth.conf",
            wait=True, user="root")
        self.frontend.run('systemctl restart dovecot',
            wait=True, user="root")

        self.setup_tb_profile(setup_openpgp=True)

        p = self.frontend.run(
            'PYTHONPATH=$HOME/dogtail LC_ALL=C.UTF-8 '
            'python3 {} --tbname={} --profile {} --imap_pw {} setup 2>&1'.format(
                self.scriptpath, self.tb_name, self.profile_dir, self.imap_pw),
            passio_popen=True)
        (stdout, _) = p.communicate()
        assert p.returncode == 0, 'Thunderbird setup failed: {}'.format(
            stdout.decode('ascii', 'ignore'))

    def tearDown(self):
        self.smtp_server.terminate()
        del self.smtp_server
        super(TC_10_Thunderbird, self).tearDown()

    def get_key_fpr(self):
        cmd = 'gpg2 -K --with-colons'
        p = self.frontend.run(cmd, passio_popen=True)
        (stdout, _) = p.communicate()
        self.assertEqual(p.returncode, 0, 'Failed to determin key id')
        keyid = stdout.decode('utf-8').split('\n')[1]
        keyid = keyid.split(':')[9]
        keyid = keyid[-16:]
        return keyid

    def setup_tb_profile(self, setup_openpgp):
        """SplitGPG Thunderbird Test Account Configuration

        Originally generated by running thunderbird for the first time
        and taking from ~/.thunderbird/<PROFILE>.default/prefs.js all
        the relevant settings. Then adding the opengpg settings.
        """

        profile_base = """
user_pref("mail.accountmanager.accounts", "account1");
user_pref("mail.accountmanager.defaultaccount", "account1");
user_pref("mail.account.account1.identities", "id1");
user_pref("mail.account.account1.server", "server1");
user_pref("mail.identity.id1.fullName", "user");
user_pref("mail.identity.id1.useremail", "user@localhost");
user_pref("mail.identity.id1.smtpServer", "smtp1");
user_pref("mail.identity.id1.compose_html", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false); // avoid message popups
user_pref("app.donation.eoy.version.viewed", 100); // avoid message popups
user_pref("mail.inappnotifications.enabled", false); // avoid message popups
"""
        imap_server = """
user_pref("mail.server.server1.userName", "user");
user_pref("mail.server.server1.hostname", "localhost");
user_pref("mail.server.server1.login_at_startup", true);
user_pref("mail.server.server1.name", "user@localhost");
user_pref("mail.server.server1.type", "imap");
user_pref("mail.server.server1.port", 143);
"""
        smtp_server = """
user_pref("mail.smtpservers", "smtp1");
user_pref("mail.smtp.defaultserver", "smtp1");
user_pref("mail.smtpserver.smtp1.username", "user");
user_pref("mail.smtpserver.smtp1.hostname", "localhost");
user_pref("mail.smtpserver.smtp1.port", 8025);
user_pref("mail.smtpserver.smtp1.authMethod", 3); // no auth
user_pref("mail.smtpserver.smtp1.try_ssl", 0);    // no encryption
"""
        open_pgp = """
user_pref("mail.openpgp.allow_external_gnupg", true);
"""
        key_fingerprint = self.get_key_fpr()
        user_account_pgp = """
user_pref("mail.identity.id1.is_gnupg_key_id", true);
user_pref("mail.identity.id1.last_entered_external_gnupg_key_id", "{}");
user_pref("mail.identity.id1.openpgp_key_id", "{}");
user_pref("mail.identity.id1.sign_mail", false);
""".format(key_fingerprint, key_fingerprint)

        self.profile_dir = "$HOME/.thunderbird/qubes.default"
        user_js_path = self.profile_dir + "/user.js"

        user_js = profile_base + imap_server + smtp_server
        if setup_openpgp:
            user_js += open_pgp + user_account_pgp

        self.frontend.run('mkdir -p {}'.format(self.profile_dir),
                          user='user', wait=True)
        p = self.frontend.run('cat > ' + user_js_path,
                          user='user', passio_popen=True)
        (stdout, _) = p.communicate(user_js.encode())
        assert p.returncode == 0, 'Thunderbird profile configuration failed: {}'\
            .format(stdout.decode('ascii', 'ignore'))

    def test_000_send_receive_default(self):
        p = self.frontend.run(
            'PYTHONPATH=$HOME/dogtail LC_ALL=C.UTF-8 '
            'python3 {} --tbname={} --profile {} --imap_pw {} send_receive '
            '--encrypted --signed 2>&1'.format(
                self.scriptpath, self.tb_name, self.profile_dir, self.imap_pw),
            passio_popen=True)
        (stdout, _) = p.communicate()
        self.assertEqual(p.returncode, 0,
            'Thunderbird send/receive failed: {}'.format(
                stdout.decode('ascii', 'ignore')))

    def test_010_send_receive_inline_signed_only(self):
        p = self.frontend.run(
            'PYTHONPATH=$HOME/dogtail LC_ALL=C.UTF-8 '
            'python3 {} --tbname={} --profile {} --imap_pw {} send_receive '
            '--encrypted --signed --inline 2>&1'.format(
                self.scriptpath, self.tb_name, self.profile_dir, self.imap_pw),
            passio_popen=True)
        (stdout, _) = p.communicate()
        self.assertEqual(p.returncode, 0,
            'Thunderbird send/receive failed: {}'.format(
                stdout.decode('ascii', 'ignore')))

    def test_020_send_receive_inline_with_attachment(self):
        p = self.frontend.run(
            'PYTHONPATH=$HOME/dogtail LC_ALL=C.UTF-8 '
            'python3 {} --tbname={} --profile {} --imap_pw {} send_receive '
            '--encrypted --signed --inline --with-attachment 2>&1'.format(
                self.scriptpath, self.tb_name, self.profile_dir, self.imap_pw),
            passio_popen=True)
        (stdout, _) = p.communicate()
        self.assertEqual(p.returncode, 0,
            'Thunderbird send/receive failed: {}'.format(
                stdout.decode('ascii', 'ignore')))


class TC_20_Evolution(SplitGPGBase):

    scriptpath = '/usr/share/split-gpg2-tests/test_evolution.py'

    def setUp(self):
        if self.template.startswith('whonix-gw'):
            self.skipTest('whonix-gw template not supported by this test')
        super(TC_20_Evolution, self).setUp()
        self.frontend.run_service('qubes.WaitForSession', wait=True,
            input='user')
        if self.frontend.run('which evolution', wait=True) != 0:
            self.skipTest('Evolution not installed')
        # use dogtail 0.9.10 directly from git, until 0.9.10 gets packaged in
        # relevant distros; 0.9.9 have problems with handling unicode
        p = self.frontend.run(
                'git clone -n https://gitlab.com/dogtail/dogtail.git && '
                'cd dogtail && '
                'git checkout 4d7923dcda92c2c44309d2a56b0bb616a1855155',
                passio_popen=True, passio_stderr=True)
        stdout, stderr = p.communicate()
        if p.returncode:
            self.skipTest(
                'dogtail installation failed: {}{}'.format(stdout, stderr))

        # if self.frontend.run(
        #         'python -c \'import dogtail,sys;'
        #         'sys.exit(dogtail.__version__ < "0.9.0")\'', wait=True) \
        #         != 0:
        #     self.skipTest('dogtail >= 0.9.0 testing framework not installed')

        p = self.frontend.run('gsettings set org.gnome.desktop.interface '
                              'toolkit-accessibility true', wait=True)
        assert p == 0, 'Failed to enable accessibility toolkit'
        if self.frontend.run(
                'ls {}'.format(self.scriptpath), wait=True):
            self.skipTest('split-gpg2-tests package not installed')

        # run as root to not deal with /var/mail permission issues
        self.frontend.run(
            'mkdir -p Mail/new Mail/cur Mail/tmp',
            wait=True)
        self.smtp_server = self.frontend.run(
            'aiosmtpd -n -c aiosmtpd.handlers.Mailbox /home/user/Mail',
            passio_popen=True)

        p = self.frontend.run(
            'PYTHONPATH=$HOME/dogtail python3 {} setup 2>&1'.format(
                self.scriptpath),
            passio_popen=True)
        (stdout, _) = p.communicate()
        assert p.returncode == 0, 'Evolution setup failed: {}'.format(
            stdout.decode('ascii', 'ignore'))

    def tearDown(self):
        self.smtp_server.terminate()
        del self.smtp_server
        super(TC_20_Evolution, self).tearDown()

    def test_000_send_receive_signed_encrypted(self):
        p = self.frontend.run(
            'PYTHONPATH=$HOME/dogtail python3 {} send_receive '
            '--encrypted --signed 2>&1'.format(
                self.scriptpath),
            passio_popen=True)
        (stdout, _) = p.communicate()
        self.assertEqual(p.returncode, 0,
            'Evolution send/receive failed: {}'.format(
                stdout.decode('ascii', 'ignore')))

    def test_010_send_receive_signed_only(self):
        p = self.frontend.run(
            'PYTHONPATH=$HOME/dogtail python3 {} send_receive '
            '--encrypted --signed 2>&1'.format(
                self.scriptpath),
            passio_popen=True)
        (stdout, _) = p.communicate()
        self.assertEqual(p.returncode, 0,
            'Evolution send/receive failed: {}'.format(
                stdout.decode('ascii', 'ignore')))

    @unittest.skip('handling attachments not done')
    def test_020_send_receive_with_attachment(self):
        p = self.frontend.run(
            'PYTHONPATH=$HOME/dogtail python3 {} send_receive '
            '--encrypted --signed --with-attachment 2>&1'.format(
                self.scriptpath),
            passio_popen=True)
        (stdout, _) = p.communicate()
        self.assertEqual(p.returncode, 0,
            'Evolution send/receive failed: {}'.format(
                stdout.decode('ascii', 'ignore')))

def list_tests():
    return (
        TC_00_Direct,
        TC_10_Thunderbird,
        TC_20_Evolution
    )
