"""Real refusals, source mutations, binary corruptions and signed review replay."""
import copy
import datetime
import hashlib
import inspect
import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from jarvis.response import defense
from release.vmtest import vmtest
from scripts.security import (
    binary_review,
    campaign,
    native_checks,
    refinement,
    review_record,
    vm_pentest,
)
from tests.security.pe_fixture import synthetic_pe


class CompletionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def test_refinement_rejects_unmodeled_effects_and_nonboolean_return(self):
        source = inspect.getsource(defense._enabled)
        self.assertIn('global_true', refinement.translate(source))
        for mutant in [source.replace('return False', 'return action.enable_flag', 1),
                       source.replace('return False', 'return eval("True")', 1),
                       source.replace('return False', 'conf.clear()\n        return False', 1)]:
            with self.assertRaises(refinement.Unsupported):
                refinement.translate(mutant)

    def test_smt_translation_matches_real_function_over_python_identity_classes(self):
        # Independent concrete evaluation of the generated SMT Boolean fragment.
        # Python identity with True must not be confused with equality (1 == True).
        source = inspect.getsource(defense._enabled)
        formula = refinement.translate(source)
        import re
        tokens = re.findall(r'\(|\)|[^\s()]+', formula)
        def evaluate(values):
            it = iter(tokens)
            def read(token):
                if token != '(':
                    return {'true': True, 'false': False, **values}[token]
                op = next(it)
                args = []
                for token in it:
                    if token == ')': break
                    args.append(read(token))
                return {'ite': lambda: args[1] if args[0] else args[2],
                        'not': lambda: not args[0], 'or': lambda: any(args),
                        'and': lambda: all(args)}[op]()
            return read(next(it))
        for global_value in [True, False, None, 1, 0, 'true', [], {}]:
            for flag_value in [True, False, None, 1, 'true']:
                for flag in ['', 'synthetic']:
                    for autonomy in ['auto', 'approve', '', None]:
                        conf={'autonomous_defense':global_value, 'synthetic':flag_value}
                        action=SimpleNamespace(enable_flag=flag,autonomy=autonomy)
                        got=evaluate({'global_true':global_value is True, 'flag_true':flag_value is True,
                                      'has_flag':bool(flag), 'is_auto':autonomy=='auto'})
                        self.assertIs(got,defense._enabled(conf,action))

    def test_elf_hardening_rejects_writable_code_and_executable_stack(self):
        data=bytearray(64+4*56+32)
        struct.pack_into('<16sHHIQQQIHHHHHH',data,0,b'\x7fELF\x02\x01'+bytes(10),3,62,1,0x1000,64,0,0,64,56,4,0,0,0)
        headers=[(1,5,0,0x1000,0,len(data),len(data),4096),
                 (3,4,0,0,0,0,0,1),(binary_review.PT_GNU_STACK,6,0,0,0,0,0,16),
                 (binary_review.PT_GNU_RELRO,4,0,0,0,0,0,1)]
        for i,row in enumerate(headers): struct.pack_into('<IIQQQQQQ',data,64+56*i,*row)
        self.assertTrue(binary_review.elf(data)['checks']['no_writable_executable_load'])
        bad=bytearray(data); struct.pack_into('<I',bad,64+4,7)
        self.assertFalse(binary_review.elf(bad)['checks']['no_writable_executable_load'])
        struct.pack_into('<I',bad,64+56*2+4,7)
        self.assertFalse(binary_review.elf(bad)['checks']['non_executable_stack'])
        for malformed in [data[:60], b'MZ'+bytes(100), data[:100]]:
            with self.assertRaises(binary_review.InvalidBinary): binary_review.elf(malformed)
        p=self.home/'link';p.symlink_to('/no-such-file')
        with self.assertRaises(OSError): binary_review.review(p)

    @staticmethod
    def _pe(**kwargs):
        return synthetic_pe(**kwargs)

    def test_pe_hardening_detects_stripped_relocations_wx_code_and_signature_absence(self):
        good = binary_review.pe(self._pe())
        self.assertTrue(good['checks']['aslr_effective'])
        self.assertTrue(good['checks']['entry_in_executable_section'])
        self.assertFalse(good['checks']['authenticode_directory_present'])
        self.assertFalse(good['signature_verified'])
        # The measured NSIS stub shape: DYNAMIC_BASE declared, relocations stripped.
        self.assertFalse(binary_review.pe(self._pe(characteristics=0x22F, reloc=(0, 0)))['checks']['aslr_effective'])
        self.assertFalse(binary_review.pe(self._pe(reloc=(0, 0)))['checks']['aslr_effective'])
        self.assertFalse(binary_review.pe(self._pe(dll=0x8120))['checks']['aslr_effective'])
        self.assertFalse(binary_review.pe(self._pe(dll=0x8060))['checks']['dep_nx_compatible'])
        self.assertFalse(binary_review.pe(self._pe(text=0xE0000020))['checks']['no_writable_executable_section'])
        self.assertFalse(binary_review.pe(self._pe(entry=0x5000))['checks']['entry_in_executable_section'])
        self.assertTrue(binary_review.pe(self._pe(cert=16))['checks']['authenticode_directory_present'])
        self.assertFalse(good['checks']['control_flow_guard'])
        self.assertTrue(binary_review.pe(self._pe(guard=True))['checks']['control_flow_guard'])
        narrow = binary_review.pe(self._pe(wide=False))
        self.assertEqual(narrow['format'], 'PE32')
        self.assertNotIn('high_entropy_aslr', narrow['checks'])
        self.assertEqual(binary_review.parse(bytes(self._pe()))['format'], 'PE32+')

    def test_pe_parser_rejects_malformed_headers_instead_of_guessing(self):
        data = self._pe(cert=16)
        bad_offset = bytearray(data); struct.pack_into('<I', bad_offset, 0x3C, len(data))
        bad_magic = bytearray(data); struct.pack_into('<H', bad_magic, 88, 0x107)
        bad_section = bytearray(data); struct.pack_into('<I', bad_section, 64 + 24 + 240 + 20, len(data))
        bad_cert = bytearray(data); struct.pack_into('<II', bad_cert, 88 + 112 + 32, 0x10, 16)
        bad_count = bytearray(data); struct.pack_into('<I', bad_count, 88 + 108, 4096)
        for malformed in [data[:60], bytes(data[:100]), bad_offset, bad_magic, bad_section, bad_cert, bad_count]:
            with self.assertRaises(binary_review.InvalidBinary):
                binary_review.pe(bytes(malformed))

    def test_native_container_has_no_network_privileges_or_writable_host_mount(self):
        argv=native_checks.container(self.home,'synthetic','test')
        self.assertIn('none',argv)
        self.assertIn('ALL',argv)
        self.assertIn('--read-only',argv)
        self.assertIn('--memory',argv)
        self.assertIn(str(self.home)+':/work:ro',argv)
        self.assertNotIn('--privileged',argv)
        self.assertNotIn('--device',argv)

    def test_vm_receipt_cannot_hide_failed_probes_or_missing_cleanup(self):
        scenario={'total':16,'passed':16,'secret_value_in_findings':False}
        guest={'security_probes':{'total':10,'passed':10,'checks':[{'ok':True} for _ in range(10)]},'scenario':scenario}
        report={'isolation':dict.fromkeys(['container_removed','run_dir_removed','base_image_unchanged'],True)}
        self.assertEqual(vm_pentest.verdict(guest,report),0)
        for mutate in [lambda g,r:g['security_probes']['checks'].clear(),
                       lambda g,r:g['security_probes']['checks'][0].update(ok=False),
                       lambda g,r:r['isolation'].update(container_removed=False),
                       lambda g,r:g['scenario'].update(secret_value_in_findings=True)]:
            g,r=copy.deepcopy(guest),copy.deepcopy(report);mutate(g,r)
            self.assertEqual(vm_pentest.verdict(g,r),1)
        self.assertEqual(vm_pentest.verdict(None,{'blocked':['CPU pressure']}),2)

    def test_security_payload_is_bound_to_guest_receipt(self):
        package=self.home/'candidate.tar.gz';package.write_bytes(b'synthetic')
        candidate={'file':str(package),'sha256':hashlib.sha256(package.read_bytes()).hexdigest(),'name':package.name}
        expected,conf=vmtest.build_payload(self.home,'tarball',candidate,security=True)
        self.assertTrue(conf['security_probes'])
        actual=(vmtest.HERE/'security_guest.py').read_bytes()
        self.assertEqual(expected['/opt/lab/security_guest.py'],hashlib.sha256(actual).hexdigest())

    def test_review_rejects_stale_unknown_future_and_unresolved_records(self):
        now=datetime.datetime.now(datetime.timezone.utc)
        record={'schema':1,'source_sha256':'a'*64,'reviewer':'synthetic-reviewer','reviewed_at':now.isoformat(),
                'independent_of_author':True,'scopes':list(review_record.SCOPES),'findings':[]}
        source={'status':'measured','sha256':'a'*64}
        self.assertTrue(review_record.validate(record,source,now))
        self.assertFalse(review_record.validate(record,{'status':'measured','sha256':'b'*64},now))
        for fields in [{'independent_of_author':False},{'schema':True},{'scopes':[[]]},
                       {'reviewed_at':(now+datetime.timedelta(days=1)).isoformat()},
                       {'reviewed_at':(now-datetime.timedelta(days=31)).isoformat()},
                       {'findings':[{'status':'open'}]}]:
            self.assertFalse(review_record.validate({**record,**fields},source,now))

    def test_real_review_signature_is_source_bound_and_tampering_is_rejected(self):
        key=self.home/'key'
        subprocess.run(['ssh-keygen','-q','-t','ed25519','-N','','-f',str(key)],check=True,timeout=10)
        now=datetime.datetime.now(datetime.timezone.utc)
        record={'schema':1,'source_sha256':'a'*64,'reviewer':'fixture','reviewed_at':now.isoformat(),
                'independent_of_author':True,'scopes':list(review_record.SCOPES),'findings':[]}
        path=self.home/'review.json';path.write_text(json.dumps(record))
        allowed=self.home/'allowed';allowed.write_text('fixture '+key.with_suffix('.pub').read_text())
        subprocess.run(['ssh-keygen','-Y','sign','-f',str(key),'-n','argus-security-review',str(path)],
                       check=True,capture_output=True,timeout=10)
        source={'status':'measured','sha256':'a'*64};sig=path.with_suffix('.json.sig')
        self.assertTrue(review_record.verify(path,sig,allowed,source,now))
        self.assertFalse(review_record.verify(path,sig,allowed,{'status':'measured','sha256':'b'*64},now))
        path.write_text(path.read_text()+' ')
        self.assertFalse(review_record.verify(path,sig,allowed,source,now))

    def test_environment_override_cannot_inject_credentials(self):
        with self.assertRaises(ValueError):
            campaign.execute(campaign.Step('fixture','sast',('true',)),self.home,
                             environment={'TYPESAFE_API_KEY':'synthetic'})

    def test_tool_receipt_rejects_modified_binaries_and_stale_manifests(self):
        root = self.home / 'repo'
        spec = root / 'scripts/security'
        spec.mkdir(parents=True)
        for name in ('requirements.txt', 'toolchain.json'):
            (spec / name).write_text('synthetic')
        tools = self.home / 'tools'
        tools.mkdir(mode=0o700)
        (tools / 'bin').mkdir()
        receipt = {'schema': 1, 'requirements_sha256': hashlib.sha256(b'synthetic').hexdigest(),
                   'manifest_sha256': hashlib.sha256(b'synthetic').hexdigest(), 'tools': {}}
        for name in ('bandit', 'semgrep', 'pip-audit', 'z3', 'gitleaks', 'cargo-audit'):
            path = tools / 'bin' / name
            path.write_bytes(b'synthetic tool bytes')
            receipt['tools'][name] = {'path': 'bin/' + name, 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        (tools / 'receipt.json').write_text(json.dumps(receipt))
        from unittest import mock
        with mock.patch.object(campaign, 'ROOT', root), mock.patch.dict(os.environ):
            self.assertEqual(len(campaign.activate_toolchain(tools)), 64)
            (spec / 'requirements.txt').write_text('changed')
            with self.assertRaises(ValueError): campaign.activate_toolchain(tools)
            (spec / 'requirements.txt').write_text('synthetic')
            (tools / 'bin/bandit').write_bytes(b'changed')
            with self.assertRaises(ValueError): campaign.activate_toolchain(tools)


if __name__=='__main__': unittest.main()
