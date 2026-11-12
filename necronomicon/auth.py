import logging
import ssl
import os
import traceback
import datetime
from hashlib import sha256, md5
from binascii import unhexlify

import ldap3
from ldap3 import Server, Connection, NTLM, ALL, SASL, KERBEROS, Tls
from ldap3.core.results import RESULT_STRONGER_AUTH_REQUIRED
from ldap3.operation.bind import bind_operation

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from impacket.krb5.ccache import CCache
from impacket.krb5.types import Principal, KerberosTime, Ticket
from impacket.krb5.asn1 import (AP_REQ, AS_REP, TGS_REP,
                                 Authenticator, seq_set)
from impacket.krb5 import constants
from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
from impacket.krb5.gssapi import CheckSumField
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.univ import noValue


class AuthenticationError(Exception):
    pass


class Auth:
    def __init__(self, username='', password='', domain='',
                 lm_hash='', nt_hash='', aeskey='', kdc=None,
                 auth_method='kerberos', channel_binding=False):
        self.username = username
        self.domain = domain.lower()
        self.userdomain = domain.lower()
        if '@' in self.username:
            self.username, self.userdomain = self.username.lower().rsplit('@', 1)
        self.password = password
        self.lm_hash = lm_hash
        self.nt_hash = nt_hash
        self.aeskey = aeskey
        self.kdc = kdc
        self.userdomain_kdc = self.domain
        self.auth_method = auth_method
        self.channel_binding = channel_binding
        self.tgt = None

    def set_kdc(self, kdc):
        self.kdc = kdc
        if self.userdomain == self.domain:
            self.userdomain_kdc = kdc

    def get_tgt(self):
        username = Principal(self.username,
                             type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        logging.info('Requesting TGT for %s@%s', self.username, self.userdomain)
        try:
            tgt, cipher, _, session_key = getKerberosTGT(
                username, self.password, self.userdomain,
                unhexlify(self.lm_hash), unhexlify(self.nt_hash),
                self.aeskey, self.userdomain_kdc)
        except Exception as exc:
            logging.debug(traceback.format_exc())
            if self.auth_method == 'kerberos':
                raise AuthenticationError(
                    'Kerberos TGT request failed: %s' % exc)
            logging.warning('TGT request failed: %s', exc)
            return

        if self.userdomain != self.domain:
            servername = Principal(
                'krbtgt/%s' % self.domain,
                type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, _, sessionkey = getKerberosTGS(
                servername, self.userdomain, self.userdomain_kdc,
                tgt, cipher, session_key)
            refneeded = True
            while refneeded:
                decoded_tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                next_realm = str(decoded_tgs['ticket']['sname']['name-string'][1])
                if next_realm.upper() == self.domain.upper():
                    refneeded = False
                else:
                    logging.debug('Following referral to %s', next_realm)
                    servername = Principal(
                        'krbtgt/%s' % self.domain,
                        type=constants.PrincipalNameType.NT_SRV_INST.value)
                    tgs, cipher, _, sessionkey = getKerberosTGS(
                        servername, next_realm, next_realm,
                        tgs, cipher, sessionkey)
            servername = Principal(
                'krbtgt/%s' % self.domain,
                type=constants.PrincipalNameType.NT_SRV_INST.value)
            tgs, cipher, _, sessionkey = getKerberosTGS(
                servername, self.domain, self.kdc,
                tgs, cipher, sessionkey)
            self.tgt = {'KDC_REP': tgs, 'cipher': cipher,
                        'sessionKey': sessionkey}
        else:
            self.tgt = {'KDC_REP': tgt, 'cipher': cipher,
                        'sessionKey': session_key}

    def load_ccache(self):
        krb5cc = os.getenv('KRB5CCNAME')
        if krb5cc is None:
            try:
                krb5cc = '/tmp/krb5cc_%u' % os.getuid()
            except AttributeError:
                krb5cc = 'nonexistingfile'

        if not os.path.isfile(krb5cc):
            logging.debug('No ccache file found at %s', krb5cc)
            return False

        logging.debug('Loading ccache: %s', krb5cc)
        ccache = CCache.loadFile(krb5cc)
        principal = 'krbtgt/%s@%s' % (self.domain.upper(), self.domain.upper())
        creds = ccache.getCredential(principal, anySPN=False)
        if creds is None:
            logging.debug('No valid credentials in ccache for %s', principal)
            return False

        TGT = creds.toTGT()
        self.tgt = TGT
        tgt = TGT['KDC_REP']

        ticket = Ticket()
        decoded_tgt = decoder.decode(tgt, asn1Spec=AS_REP())[0]
        ticket.from_asn1(decoded_tgt['ticket'])
        tgt_principal = Principal()
        tgt_principal.from_asn1(decoded_tgt, 'crealm', 'cname')
        expected = '%s@%s' % (self.username.lower(), self.domain.upper())
        if expected.upper() != str(tgt_principal).upper():
            logging.warning('ccache principal mismatch: %s != %s',
                            tgt_principal, expected)
            return False

        logging.info('Using TGT from ccache')
        return True

    def _build_server(self, ip, protocol, gc=False):
        port_map = {
            ('ldaps', True): 3269, ('ldap', True): 3268,
            ('ldaps', False): 636, ('ldap', False): 389,
        }
        port = port_map.get((protocol, gc), 389)

        if protocol == 'ldaps' or self.channel_binding:
            if self.channel_binding and not hasattr(ldap3, 'TLS_CHANNEL_BINDING'):
                raise AuthenticationError(
                    'LDAP channel binding requires patched ldap3: '
                    'pip3 install git+https://github.com/ly4k/ldap3')
            tls = Tls(validate=ssl.CERT_NONE,
                      version=ssl.PROTOCOL_TLSv1_2,
                      ciphers='ALL:@SECLEVEL=0')
            return Server('%s://%s:%d' % ('ldaps', ip, port),
                          use_ssl=True, get_info=ALL, tls=tls)
        return Server('%s://%s:%d' % (protocol, ip, port), get_info=ALL)

    def get_ldap_connection(self, hostname='', ip='', base_dn='',
                            protocol='ldap', gc=False):
        server = self._build_server(ip, protocol, gc)
        if self.nt_hash:
            lm = self.lm_hash or 'aad3b435b51404eeaad3b435b51404ee'
            ldappass = '%s:%s' % (lm, self.nt_hash)
        else:
            ldappass = self.password
        ldaplogin = '%s\\%s' % (self.userdomain, self.username)

        bound = False

        if self.auth_method == 'kerberos':
            if self.tgt is None:
                raise AuthenticationError(
                    'Kerberos requested but no TGT available')
            conn = Connection(server, user=ldaplogin, auto_referrals=False,
                              password=ldappass, authentication=SASL,
                              sasl_mechanism=KERBEROS, receive_timeout=60,
                              auto_range=True)
            logging.debug('LDAP Kerberos bind to %s', hostname)
            try:
                bound = self._ldap_kerberos(conn, hostname)
            except Exception:
                logging.debug(traceback.format_exc())
                raise AuthenticationError(
                    'Kerberos LDAP bind failed. Check SPN and TGT.')

        elif self.auth_method == 'ntlm':
            logging.debug('LDAP NTLM bind to %s', hostname)
            if self.channel_binding:
                from ldap3 import TLS_CHANNEL_BINDING
                conn = Connection(server, user=ldaplogin, password=ldappass,
                                  authentication=NTLM, auto_referrals=False,
                                  receive_timeout=60, auto_range=True,
                                  channel_binding=TLS_CHANNEL_BINDING)
            else:
                conn = Connection(server, user=ldaplogin, password=ldappass,
                                  authentication=NTLM, auto_referrals=False,
                                  receive_timeout=60, auto_range=True)
            bound = conn.bind()
        else:
            raise AuthenticationError('Unknown auth method: %s' % self.auth_method)

        if not bound:
            result = conn.result
            if result['result'] == RESULT_STRONGER_AUTH_REQUIRED:
                if protocol == 'ldap':
                    logging.warning('LDAP signing required, upgrading to LDAPS')
                    return self.get_ldap_connection(
                        hostname, ip, base_dn, 'ldaps', gc)
                elif not self.channel_binding:
                    logging.warning('LDAPS rejected, trying channel binding')
                    self.channel_binding = True
                    return self.get_ldap_connection(
                        hostname, ip, base_dn, 'ldaps', gc)
            raise AuthenticationError(
                'LDAP bind failed: %s (code %s)' %
                (result.get('message', ''), result.get('result', '')))
        return conn

    def _ldap_kerberos(self, connection, hostname):
        connection.open(read_server_info=False)
        username = Principal(self.username,
                             type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        servername = Principal(
            'ldap/%s' % hostname,
            type=constants.PrincipalNameType.NT_SRV_INST.value)
        tgs, cipher, _, sessionkey = getKerberosTGS(
            servername, self.domain, self.kdc,
            self.tgt['KDC_REP'], self.tgt['cipher'], self.tgt['sessionKey'])

        blob = SPNEGO_NegTokenInit()
        blob['MechTypes'] = [TypesMech['MS KRB5 - Microsoft Kerberos 5']]

        tgs = decoder.decode(tgs, asn1Spec=TGS_REP())[0]
        ticket = Ticket()
        ticket.from_asn1(tgs['ticket'])

        apReq = AP_REQ()
        apReq['pvno'] = 5
        apReq['msg-type'] = int(constants.ApplicationTagNumbers.AP_REQ.value)
        apReq['ap-options'] = constants.encodeFlags([])
        seq_set(apReq, 'ticket', ticket.to_asn1)

        authenticator = Authenticator()
        authenticator['authenticator-vno'] = 5
        authenticator['crealm'] = self.userdomain
        seq_set(authenticator, 'cname', username.components_to_asn1)
        now = datetime.datetime.utcnow()
        authenticator['cusec'] = now.microsecond
        authenticator['ctime'] = KerberosTime.to_asn1(now)

        bindings = None
        try:
            peercert = connection.socket.getpeercert(binary_form=True)
        except AttributeError:
            peercert = None
        if peercert:
            cert = x509.load_der_x509_certificate(peercert, default_backend())
            hash_algo = cert.signature_hash_algorithm
            if isinstance(hash_algo, (hashes.MD5, hashes.SHA1)):
                digest = hashes.Hash(hashes.SHA256(), default_backend())
            else:
                digest = hashes.Hash(hash_algo, default_backend())
            digest.update(peercert)
            cert_digest = digest.finalize()
            cb_data = b'tls-server-end-point:' + cert_digest
            cb_struct = (b'\x00' * 8 + b'\x00' * 8
                         + len(cb_data).to_bytes(4, 'little') + cb_data)
            bindings = md5(cb_struct).digest()

        authenticator['cksum'] = noValue
        authenticator['cksum']['cksumtype'] = 0x8003
        chkField = CheckSumField()
        chkField['Lgth'] = 16
        if bindings:
            chkField['Bnd'] = bindings
        chkField['Flags'] = 0
        authenticator['cksum']['checksum'] = chkField.getData()

        enc_auth = encoder.encode(authenticator)
        enc_auth = cipher.encrypt(sessionkey, 11, enc_auth, None)

        apReq['authenticator'] = noValue
        apReq['authenticator']['etype'] = cipher.enctype
        apReq['authenticator']['cipher'] = enc_auth

        blob['MechToken'] = encoder.encode(apReq)

        request = bind_operation(connection.version, SASL, None, None,
                                 connection.sasl_mechanism, blob.getData())
        response = connection.post_send_single_response(
            connection.send('bindRequest', request, None))[0]
        connection.result = response
        if response['result'] == 0:
            connection.bound = True
            connection.refresh_server_info()
        return response['result'] == 0
