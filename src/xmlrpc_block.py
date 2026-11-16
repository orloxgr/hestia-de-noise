"""Explicit per-site XML-RPC rejection, separate from request rate limits."""

import hashlib
import ipaddress
import urllib.error
import urllib.request

DEFAULT = {'enabled': False, 'targets': [], 'exceptions': {},
           'global_exceptions': []}
PATH = r'^/(?:[^/]+/)*xmlrpc\.php(?:/.*)?$'
JETPACK_URL = 'https://jetpack.com/ips-v4.txt'


def jetpack_ips():
    """Read the complete official list; never modify policy or fetch a user URL."""
    try:
        with urllib.request.urlopen(JETPACK_URL, timeout=30) as response:
            values = response.read().decode('utf-8').splitlines()
        networks = list(dict.fromkeys(str(ipaddress.IPv4Network(value.strip(), strict=False))
                                     for value in values if value.strip()))
        if not networks:
            raise ValueError('the published IP list is empty')
    except (OSError, UnicodeError, ValueError, urllib.error.URLError) as error:
        raise ValueError('Could not load the official Jetpack IP list: ' + str(error)) from error
    return networks


def validate(settings, target):
    if (not isinstance(settings, dict) or set(settings) != set(DEFAULT)
            or type(settings['enabled']) is not bool or not isinstance(settings['targets'], list)):
        raise ValueError('Invalid XML-RPC disable settings')
    settings['targets'] = list(dict.fromkeys(target(value) for value in settings['targets']))
    if not isinstance(settings['exceptions'], dict):
        raise ValueError('XML-RPC IP exceptions must be grouped by site')
    exceptions = {}
    for site, addresses in settings['exceptions'].items():
        site = target(site)
        if not isinstance(addresses, list):
            raise ValueError('XML-RPC exceptions must be IP addresses or CIDRs, one per line')
        networks = []
        for address in addresses:
            if not isinstance(address, str) or '%' in address:
                raise ValueError('Invalid XML-RPC exception IP address or CIDR')
            try:
                network = str(ipaddress.ip_network(address, strict=False))
            except ValueError as error:
                raise ValueError('Invalid XML-RPC exception IP address or CIDR: ' + address) from error
            if network not in networks:
                networks.append(network)
        if networks:
            exceptions[site] = networks
    settings['exceptions'] = exceptions
    addresses = settings['global_exceptions']
    if not isinstance(addresses, list):
        raise ValueError('Global XML-RPC exceptions must be IP addresses or CIDRs, one per line')
    normalized = []
    for address in addresses:
        if not isinstance(address, str) or '%' in address:
            raise ValueError('Invalid global XML-RPC exception IP address or CIDR')
        try:
            network = str(ipaddress.ip_network(address, strict=False))
        except ValueError as error:
            raise ValueError('Invalid global XML-RPC exception IP address or CIDR: ' + address) from error
        if network not in normalized:
            normalized.append(network)
    settings['global_exceptions'] = normalized


def compile_maps(settings, sites, scope_map, pattern):
    # An empty selection means no sites, never an implicit server-wide block.
    selected = [site for site in sites if site['key'] in settings['targets'] and site.get('kind') != 'mail']
    lines = scope_map('hdn_xmlrpc_disabled_site', settings, selected)
    allowed_hosts = []
    for site in selected:
        networks = settings['exceptions'].get(site['key'], [])
        if not settings['enabled'] or not networks or not site.get('supported', True) or site.get('suspended'):
            continue
        variable = 'hdn_xmlrpc_allow_' + hashlib.sha256(site['key'].encode()).hexdigest()[:16]
        lines += ['geo $remote_addr $' + variable + ' {', '    default 0;']
        lines += ['    ' + network + ' 1;' for network in networks]
        lines += ['}']
        # Hestia's canonical server_name covers aliases without trusting Host/XFF.
        allowed_hosts.append('    ' + site.get('domain', site['key'].split('/')[1]) + ' $' + variable + ';')
    lines += ['map $server_name $hdn_xmlrpc_exempt {', '    default 0;', *allowed_hosts, '}']
    lines += ['geo $remote_addr $hdn_xmlrpc_global_exempt {', '    default 0;']
    lines += ['    ' + network + ' 1;' for network in settings['global_exceptions']]
    lines += ['}']
    return lines + [
        'map $uri $hdn_xmlrpc_disabled_path {', '    default 0;', '    ' + pattern(PATH) + ' 1;', '}',
        'map "$hdn_mode:$hdn_xmlrpc_disabled_site:$hdn_xmlrpc_disabled_path:$hdn_xmlrpc_exempt:$hdn_xmlrpc_global_exempt" $hdn_xmlrpc_disabled {',
        '    default 0;', '    ~^(observe|enforce):1:1:0:0$ 1;', '}']
