import carthage
from carthage import *
from carthage_aws import *
from pathlib import Path
import cryptography
import logging
import dataclasses
import re
import pathlib

@dataclasses.dataclass()
class PkiReference:
    source: object
    ref: object
    obj: object

@inject_autokwargs(ainjector=AsyncInjector)
class PkiIndexer(AsyncInjectable):

    def __init__(self, *, baseurl=None, **kwargs):
        super().__init__(**kwargs)
        self.keys_by_nums = dict()
        self.csrs_by_nums = dict()
        self.csrs_by_dnsname = dict()
        self.csrs_by_subject = dict()
        self.certs_by_nums = dict()
        self.certs_by_dnsname = dict()
        self.certs_by_subject = dict()

    async def async_ready(self):
        await self.index_certificates()
        # await self.relocate_certificates()
        await super().async_ready()

    async def index_certificates(self):
        return

    async def relocate_certificates(self):
        return

    def _process_key(self, k, key):

        pk = key.public_key()
        nums = pk.public_numbers()
        self.keys_by_nums[nums] = PkiReference(source=self, ref=k, obj=key)

    def _process_certificate(self, k, cert):

        pk = cert.public_key()
        nums = pk.public_numbers()
        ref = PkiReference(source=self, ref=k, obj=cert)
        self.certs_by_nums[nums] = ref
        self.certs_by_subject[cert.subject] = ref

        try:
            for v in cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName).value:
                if v.value not in self.certs_by_dnsname:
                    self.certs_by_dnsname[v.value] = []
                self.certs_by_dnsname[v.value].append(ref)
        except cryptography.x509.extensions.ExtensionNotFound:
            pass

    def _process_certificate_request(self, k, csr):

        pk = csr.public_key()
        nums = pk.public_numbers()
        ref = PkiReference(source=self, ref=k, obj=csr)
        self.csrs_by_nums[nums] = ref
        self.csrs_by_subject[csr.subject] = ref

        try:
            for v in csr.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName).value:
                self.csrs_by_dnsname[v.value] = ref
        except cryptography.x509.extensions.ExtensionNotFound:
            pass

    def _iterate_pem(self, s):

        s = s + b'\n'
        while True:
            m = re.search(b'^-----BEGIN ([A-Z][A-Z ]+[A-Z])-----[\r\n]+', s, re.MULTILINE)
            if m is None: return
            m2 = re.search(b'^-----END ' + m.group(1) + b'-----[\r\n]+', s[m.span()[1]:], re.MULTILINE)
            assert m2, breakpoint()
            r = s[m.span()[0] : m2.span()[1] + m.span()[1]]
            s = s[m2.span()[1] + m.span()[1]:]
            yield r

    def _process_bytes(self, k, ss):

        ret = []

        try:
            cert = cryptography.x509.load_der_x509_certificate(ss)
            self._process_certificate(k, cert)
            return [cert]
        except ValueError:
            pass

        for s in self._iterate_pem(ss):

            if (b'-----BEGIN PRIVATE KEY-----' in s) \
               or (b'-----BEGIN RSA PRIVATE KEY-----' in s):
                key = cryptography.hazmat.primitives.serialization.load_pem_private_key(s, password=None)
                self._process_key(k, key)
                ret.append(key)
            elif b'-----BEGIN CERTIFICATE-----' in s:
                cert = cryptography.x509.load_pem_x509_certificate(s)
                self._process_certificate(k, cert)
                ret.append(cert)
            elif b'-----BEGIN CERTIFICATE REQUEST-----' in s:
                csr = cryptography.x509.load_pem_x509_csr(s)
                self._process_certificate_request(k, csr)
                ret.append(csr)
            else:
                raise ValueError(f'unknown format for {s}')

        return ret

    async def trust_store(self):
        return None

    async def trustroot_for(self, hn):

        certs = await self.certificates_for(hn, include_trustroot=True)
        cur = certs[-1]
        assert (cur.issuer == cur.subject)
        return cur

    async def validate_for(self, manifest):

        missing = dict()
        for fqdn, data in manifest.items():
            if fqdn not in self.certs_by_dnsname:
                missing[fqdn] = data
        return missing

    async def validate(self):

        # For now, we only care about having the key for leaf
        # certificates with a SAN

        for nums, certinfo in self.certs_by_nums.items():
            cert = certinfo.obj
            try:
                san = cert.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName)
                if nums not in self.keys_by_nums:
                    logging.warn(f'no key for {cert} with {san}')
                    continue
            except cryptography.x509.extensions.ExtensionNotFound:
                pass

    async def key_for(self, fqdn):

        cert = await self.certificate_for(fqdn)
        nums = cert.public_key().public_numbers()
        key = self.keys_by_nums[nums].obj
        return key

    async def certificate_for(self, fqdn):
        for cert in await self.certificates_for(fqdn):
            return cert

    async def certificates_for(self, fqdn, include_trustroot=False, required=True):

        cur = None
        ret = []
        
        if fqdn in self.certs_by_dnsname:
            options = self.certs_by_dnsname[fqdn]
            if len(options) > 1:
                orefs = [ str(o.ref) for o in options ]
                raise ValueError(f'certificate for {fqdn} found in multiple locations: {orefs}')
            cur = options[0].obj
        
        wildcard = '*' + '.' + fqdn.partition('.')[2]

        if cur is None:
            if wildcard in self.certs_by_dnsname:
                options = self.certs_by_dnsname[wildcard]
                if len(options) > 1:
                    breakpoint() # raise ValueError(options)
                cur = options[0].obj

        if cur is None:
            if required:
                raise KeyError(f'no certificate found for {fqdn} or {wildcard}')
            else:
                return []

        while True:
            if (cur.issuer == cur.subject):
                if include_trustroot:
                    ret.append(cur)
                break
            ret.append(cur)
            cur = self.certs_by_subject[cur.issuer].obj
        return ret

@inject_autokwargs(ainjector=AsyncInjector, config_layout=ConfigLayout)
class PkiIndexerZip(PkiIndexer):

    def __init__(self, path, **kwargs):
        super().__init__(**kwargs)
        self.path = path

    async def relocate_certificates(self):
        return

    async def index_certificates(self):

        import zipfile
        zf = zipfile.ZipFile(self.path)

        for zi in zf.filelist:
            s = zf.open(zi).read()
            self._process_bytes(zi.filename, s)

        await self.validate()

@inject_autokwargs(ainjector=AsyncInjector, config_layout=ConfigLayout)
class PkiIndexerPath(PkiIndexer):

    def __init__(self, path, **kwargs):
        super().__init__(**kwargs)
        self.path = path

    async def relocate_certificates(self):
        return

    async def index_certificates(self):

        p = pathlib.Path(self.path)

        for fn in p.glob('**/*'):
            if fn.is_file():
                s = fn.open('rb').read()
                self._process_bytes(fn, s)

        await self.validate()

@inject_autokwargs(ainjector=AsyncInjector, config_layout=ConfigLayout)
class PkiIndexerMulti(PkiIndexer):

    def __init__(self, *args, **kwargs):
        super().__init__(**kwargs)
        self.args = args

    async def relocate_certificates(self):
        return

    async def index_certificates(self):

        for x in self.args:
            await x.async_become_ready()

        for x in self.args:
            for attr in ['keys_by_nums', 'certs_by_nums', 'certs_by_dnsname', 'certs_by_subject']:
                f = getattr(x, attr)
                t = getattr(self, attr)
                for k, v in f.items():
                    t[k] = v
