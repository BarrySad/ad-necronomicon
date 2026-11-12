import logging

import ldap3
from dns import resolver
from ldap3 import ALL_ATTRIBUTES, BASE, SUBTREE
from ldap3.core.exceptions import (LDAPNoSuchObjectResult, LDAPSocketReceiveError,
                                    LDAPSocketSendError, LDAPCommunicationError)
from ldap3.protocol.microsoft import security_descriptor_control

from necronomicon.auth import Auth, AuthenticationError
from necronomicon.utils import domain2ldap, ldap2domain

LDAP_SERVER_SHOW_DELETED_OID = '1.2.840.113556.1.4.417'
LDAP_SERVER_SHOW_RECYCLED_OID = '1.2.840.113556.1.4.2064'


class LDAPSession:
    def __init__(self, domain, auth, nameserver=None, dc=None,
                 use_ldaps=False, dns_tcp=False, dns_timeout=3.0):
        self.domain = domain
        self.auth = auth
        self.base_dn = domain2ldap(domain)
        self.hostname = dc
        self.protocol = 'ldaps' if use_ldaps else 'ldap'
        self.dns_tcp = dns_tcp
        self.ldap = None
        self._ip = None

        self.dnsresolver = resolver.Resolver()
        if nameserver:
            self.dnsresolver.nameservers = [nameserver]
        self.dnsresolver.cache = resolver.Cache()
        self.dnsresolver.timeout = float(dns_timeout)
        self.dnsresolver.lifetime = float(dns_timeout)

    def _resolve_dc(self):
        if self.hostname:
            return self.hostname
        logging.debug('Discovering DC via DNS SRV for %s', self.domain)
        query = '_ldap._tcp.pdc._msdcs.%s.' % self.domain
        try:
            q = self.dnsresolver.resolve(query, 'SRV', tcp=self.dns_tcp)
            for r in q:
                dc = str(r.target).rstrip('.')
                logging.info('Discovered DC: %s', dc)
                self.hostname = dc
                return dc
        except (resolver.NXDOMAIN, resolver.Timeout, resolver.NoAnswer) as e:
            raise ConnectionError('DC discovery failed for %s: %s' % (self.domain, e))
        raise ConnectionError('No DC found for %s' % self.domain)

    def _resolve_kdc(self):
        kquery = '_kerberos._tcp.dc._msdcs.%s.' % self.domain
        try:
            q = self.dnsresolver.resolve(kquery, 'SRV', tcp=self.dns_tcp)
            for r in q:
                kdc = str(r.target).rstrip('.')
                logging.debug('Found KDC: %s', kdc)
                return kdc
        except (resolver.NXDOMAIN, resolver.Timeout, resolver.NoAnswer):
            pass
        return None

    def _resolve_ip(self, hostname):
        try:
            q = self.dnsresolver.resolve(hostname, 'A', tcp=self.dns_tcp)
            for rdata in q:
                return rdata.address
        except Exception:
            pass
        try:
            q = self.dnsresolver.resolve(hostname, 'AAAA', tcp=self.dns_tcp)
            for rdata in q:
                return '[%s]' % rdata.address
        except Exception:
            pass
        return None

    def connect(self):
        self._resolve_dc()
        if self.auth.auth_method == 'kerberos':
            if not self.auth.kdc:
                kdc = self._resolve_kdc()
                if kdc:
                    self.auth.set_kdc(kdc)
                else:
                    self.auth.set_kdc(self.hostname)
            if self.auth.tgt is None:
                if not self.auth.load_ccache():
                    self.auth.get_tgt()

        ip = self._resolve_ip(self.hostname)
        if not ip:
            raise ConnectionError('Could not resolve %s to an IP' % self.hostname)
        self._ip = ip

        logging.info('Connecting to %s (%s) via %s', self.hostname, ip, self.protocol)
        self.ldap = self.auth.get_ldap_connection(
            hostname=self.hostname, ip=ip,
            base_dn=self.base_dn, protocol=self.protocol)
        return self.ldap is not None

    def search(self, search_filter='(objectClass=*)', attributes=None,
               search_base=None, search_scope=SUBTREE, controls=None,
               query_sd=False):
        if self.ldap is None:
            self.connect()
        if search_base is None:
            search_base = self.base_dn
        if attributes is None:
            attributes = ALL_ATTRIBUTES

        sd_controls = None
        if query_sd:
            sd_controls = security_descriptor_control(sdflags=0x05)

        merged = list(sd_controls or []) + list(controls or [])

        try:
            sresult = self.ldap.extend.standard.paged_search(
                search_base, search_filter,
                attributes=attributes,
                paged_size=200,
                search_scope=search_scope,
                controls=merged or None,
                generator=True)
            for entry in sresult:
                if entry['type'] != 'searchResEntry':
                    continue
                yield entry
        except LDAPNoSuchObjectResult:
            logging.warning('Search base does not exist: %s', search_base)
        except (LDAPSocketReceiveError, LDAPSocketSendError,
                LDAPCommunicationError) as e:
            logging.error('LDAP connection lost during search: %s', e)

    def get_single(self, dn, attributes=None):
        if attributes is None:
            attributes = ALL_ATTRIBUTES
        try:
            results = self.ldap.extend.standard.paged_search(
                dn, '(objectClass=*)',
                search_scope=BASE,
                attributes=attributes,
                paged_size=10,
                generator=False)
        except LDAPNoSuchObjectResult:
            return None
        except (LDAPSocketReceiveError, LDAPSocketSendError,
                LDAPCommunicationError):
            logging.error('Connection lost reading %s', dn)
            return None
        for entry in results:
            if entry['type'] != 'searchResEntry':
                continue
            return entry
        return None

    def get_deleted_object_controls(self):
        controls = [(LDAP_SERVER_SHOW_DELETED_OID, True, None)]
        try:
            supported = [c[0] for c in self.ldap.server.info.supported_controls]
        except (AttributeError, TypeError):
            supported = []
        if LDAP_SERVER_SHOW_RECYCLED_OID in supported:
            controls.append((LDAP_SERVER_SHOW_RECYCLED_OID, False, None))
        return controls

    def get_recycle_bin_info(self):
        info = {'enabled': False, 'deleted_object_lifetime': None,
                'tombstone_lifetime': None}
        try:
            conf_nc = self.ldap.server.info.other['configurationNamingContext'][0]
        except (KeyError, IndexError, TypeError):
            logging.warning('Could not determine configurationNamingContext')
            return info
        ds_dn = 'CN=Directory Service,CN=Windows NT,CN=Services,%s' % conf_nc
        ds = self.get_single(ds_dn, ['tombstoneLifetime',
                                      'msDS-DeletedObjectLifetime'])
        if ds:
            attrs = ds['attributes']
            info['tombstone_lifetime'] = attrs.get('tombstoneLifetime') or None
            info['deleted_object_lifetime'] = (
                attrs.get('msDS-DeletedObjectLifetime') or None)
        feature_dn = ('CN=Recycle Bin Feature,CN=Optional Features,%s' % ds_dn)
        feature = self.get_single(feature_dn, ['msDS-EnabledFeatureBL'])
        if feature and feature['attributes'].get('msDS-EnabledFeatureBL'):
            info['enabled'] = True
        return info
