"""Owned IPv6 companion to Hestia's IPv4-only native ban commands."""
import ipaddress
import json
from pathlib import Path
import shlex
import subprocess

import storage

CHAIN = 'hdn-denoise-v6'
MARKER = 'hestia-de-noise-v6'
BINARY = '/usr/sbin/ip6tables'
JUMP = ['-p', 'tcp', '-m', 'multiport', '--dports', '80,443', '-m', 'comment', '--comment', MARKER, '-j', CHAIN]


class Firewall:
    def __init__(self, state):
        self.state = Path(state)
        self.path = self.state / 'native-ipv6.json'

    def command(self, *args, optional=False):
        value = subprocess.run([BINARY, '-w', *args], capture_output=True, text=True)
        if value.returncode and not optional:
            raise RuntimeError('Native IPv6 firewall operation failed')
        return value

    def saved(self):
        raw = storage.read(self.path)
        if raw is None:
            return None
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {'addon', 'addresses'} or value['addon'] != MARKER or not isinstance(value['addresses'], list):
            raise ValueError('Untrusted IPv6 firewall ownership record')
        return {str(ipaddress.IPv6Address(address)) for address in value['addresses']}

    def save(self, addresses):
        storage.private_directory(self.state)
        storage.replace(self.path, storage.json_bytes({'addon': MARKER, 'addresses': sorted(addresses)}), 0o600)

    def inspect(self):
        saved = self.saved()
        if saved is None and not Path(BINARY).exists():
            return set(), set()
        rules = self.command('-S', CHAIN, optional=True)
        if rules.returncode:
            if saved is None:
                return set(), set()
            # If IPv6 is unavailable, preserve a pending error, never claim a ban.
            check = self.command('-S', 'INPUT')
            return saved, set()
        if saved is None:
            raise ValueError('Refusing an unmanaged IPv6 De-Noise chain')
        active = set()
        for line in rules.stdout.splitlines():
            tokens = shlex.split(line)
            if tokens in (['-N', CHAIN], ['-A', CHAIN, '-j', 'RETURN']):
                continue
            if len(tokens) != 6 or tokens[:3] != ['-A', CHAIN, '-s'] or tokens[4:] != ['-j', 'DROP']:
                raise ValueError('IPv6 De-Noise chain contains unmanaged rules')
            network = ipaddress.ip_network(tokens[3], strict=True)
            if network.version != 6 or network.prefixlen != 128:
                raise ValueError('IPv6 De-Noise bans must be individual addresses')
            active.add(str(network.network_address))
        jumps = []
        for line in self.command('-S', 'INPUT').stdout.splitlines():
            tokens = shlex.split(line)
            if '-j' not in tokens or tokens[tokens.index('-j') + 1] != CHAIN:
                continue
            # Some backends explicitly print the implicit tcp matcher.
            for index in range(len(tokens) - 1):
                if tokens[index:index + 2] == ['-m', 'tcp']:
                    del tokens[index:index + 2]
                    break
            jumps.append(tokens)
        if jumps and jumps != [['-A', 'INPUT', *JUMP]]:
            raise ValueError('IPv6 De-Noise jump has an unexpected scope')
        return saved, active if jumps else set()

    def add(self, address):
        address = str(ipaddress.IPv6Address(address))
        saved, active = self.inspect()
        # The ownership record is written before changes so interrupted work is
        # recoverable, after inspect has refused any pre-existing unmanaged chain.
        saved.add(address)
        self.save(saved)
        if self.command('-S', CHAIN, optional=True).returncode:
            self.command('-N', CHAIN)
            self.command('-A', CHAIN, '-j', 'RETURN')
        if self.command('-C', 'INPUT', *JUMP, optional=True).returncode:
            self.command('-I', 'INPUT', *JUMP)
        if address not in active:
            if self.command('-C', CHAIN, '-s', address, '-j', 'DROP', optional=True).returncode:
                self.command('-I', CHAIN, '1', '-s', address, '-j', 'DROP')

    def remove(self, address):
        address = str(ipaddress.IPv6Address(address))
        saved, active = self.inspect()
        if not self.command('-C', CHAIN, '-s', address, '-j', 'DROP', optional=True).returncode:
            self.command('-D', CHAIN, '-s', address, '-j', 'DROP')
        saved.discard(address)
        self.save(saved)

    def drop(self):
        saved, active = self.inspect()
        if saved or active:
            raise ValueError('Refusing to remove a nonempty IPv6 De-Noise chain')
        if self.saved() is None:
            return
        if not self.command('-C', 'INPUT', *JUMP, optional=True).returncode:
            self.command('-D', 'INPUT', *JUMP)
        rules = self.command('-S', CHAIN, optional=True)
        if not rules.returncode:
            if '-A ' + CHAIN + ' -j RETURN' in rules.stdout:
                self.command('-D', CHAIN, '-j', 'RETURN')
            self.command('-X', CHAIN)
        self.path.unlink(missing_ok=True)
