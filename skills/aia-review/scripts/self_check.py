#!/usr/bin/env python3
"""Synthetic behavioral checks. No real drawings, human signoffs, models or network calls."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from inventory_inputs import inventory
from render_report import render
from validate_review import validate

HERE=Path(__file__).resolve().parent
ASSETS=HERE.parent/'assets'
BUNDLE=HERE.parents[2]

def sample(complete=False):
    filename='example-complete.json' if complete else 'example-review.json'
    return json.loads((ASSETS/filename).read_text(encoding='utf-8'))

def make_link(link,target):
    """Directory link: symlink where allowed, junction on unprivileged Windows.

    Windows refuses symlinks without SeCreateSymbolicLinkPrivilege (WinError
    1314), but mklink /J needs no privilege and is redirect enough to exercise
    the root-containment checks.
    """
    try:
        link.symlink_to(target,target_is_directory=True)
        return
    except (OSError,NotImplementedError):
        if os.name!='nt':
            raise
    subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],check=True,capture_output=True)

class ReviewChecks(unittest.TestCase):
    def check(self,d,verify=True,root=ASSETS):
        return validate(d,root,verify)

    def assertInvalid(self,d,fragment=None):
        r=self.check(d)
        self.assertFalse(r['schema_valid'],r)
        if fragment:
            self.assertTrue(any(fragment in e for e in r['errors']),r)

    def test_pending_draft_can_be_valid_but_blocked(self):
        r=self.check(sample())
        self.assertTrue(r['schema_valid'],r)
        self.assertEqual(r['signoff_readiness'],'blocked')
        self.assertTrue(any('pending' in b for b in r['blockers']))

    def test_complete_synthetic_flow_reaches_record_readiness(self):
        r=self.check(sample(True))
        self.assertEqual(r['errors'],[])
        self.assertEqual(r['blockers'],[])
        self.assertEqual(r['signoff_readiness'],'ready_for_human_signoff')
        self.assertEqual(r['mode'],'synthetic')

    def test_no_rehash_cannot_claim_ready(self):
        r=self.check(sample(True),verify=False)
        self.assertTrue(r['schema_valid'])
        self.assertFalse(r['source_files_verified'])
        self.assertEqual(r['signoff_readiness'],'blocked')

    def test_current_file_changed_invalidates_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for f in ASSETS.glob('synthetic-*.txt'):
                (root/f.name).write_bytes(f.read_bytes())
            (root/'synthetic-input.txt').write_text('changed',encoding='utf-8')
            r=self.check(sample(),root=root)
            self.assertFalse(r['schema_valid'])
            self.assertTrue(any('current bytes' in e for e in r['errors']))

    def test_evidence_hash_drift_is_rejected(self):
        d=sample(); d['checks'][0]['evidence'][0]['source_sha256']='0'*64
        self.assertInvalid(d,'evidence hash')

    def test_unplanned_or_missing_checks_are_not_silent(self):
        d=sample(); d['project']['planned_check_ids'].append('MISSING')
        self.assertInvalid(d,'exactly match')

    def test_zero_loaded_rules_and_zero_checks_is_never_ready(self):
        d=sample(True)
        d['rules']=[]; d['checks']=[]; d['findings']=[]
        d['project']['planned_check_ids']=[]
        r=self.check(d)
        self.assertEqual(r['signoff_readiness'],'blocked')
        self.assertTrue(any('No checks' in b for b in r['blockers']))

    def test_unsupported_is_valid_but_uncovered(self):
        d=sample(); c=d['checks'][0]
        c['status']='unsupported'; c['result']=None; c['comparison']=None
        c['reason']='No geometry reader available'; d['findings']=[]
        r=self.check(d)
        self.assertTrue(r['schema_valid'],r)
        self.assertEqual(r['stats']['evaluated'],0)
        self.assertEqual(r['stats']['status_counts'],{'unsupported':1})
        self.assertEqual(r['signoff_readiness'],'blocked')

    def test_rule_error_cannot_be_hidden_by_zero_findings(self):
        d=sample(); c=d['checks'][0]
        c.update(status='error',result=None,comparison=None,reason='Extractor failed')
        d['findings']=[]
        r=self.check(d)
        self.assertTrue(r['schema_valid'],r)
        self.assertTrue(any('error' in b for b in r['blockers']))

    def test_normalized_unit_value_must_reproduce(self):
        d=sample(); d['checks'][0]['comparison']['normalized_value']='1000'
        self.assertInvalid(d,'unit conversion')

    def test_length_is_not_area(self):
        d=sample(); d['checks'][0]['comparison']['observed_unit']='m2'
        self.assertInvalid(d,'incompatible units')

    def test_threshold_drift_is_rejected(self):
        d=sample(); d['checks'][0]['comparison']['threshold']='1.1'
        self.assertInvalid(d,'threshold differs')

    def test_neighboring_quantity_is_not_accepted(self):
        d=sample(); d['checks'][0]['comparison']['quantity']='another_quantity'
        self.assertInvalid(d,'quantity differs')

    def test_missing_applicability_conditions_rejected(self):
        d=sample(); d['checks'][0]['comparison']['conditions_verified']=False
        self.assertInvalid(d,'conditions were not verified')

    def test_signal_cannot_be_silently_dropped(self):
        d=sample(); d['findings']=[]
        self.assertInvalid(d,'signal has no linked finding')

    def test_fake_no_signal_is_recomputed(self):
        d=sample(); d['checks'][0]['result']='no_signal'; d['findings']=[]
        self.assertInvalid(d,'contradicts')

    def test_ge_boundary_passes_but_gt_boundary_signals(self):
        for op,result in [('ge','no_signal'),('gt','signal')]:
            d=sample(); c=d['checks'][0]; r=d['rules'][0]
            r['criterion']['operator']=op
            c['comparison'].update(observed_value='1500',normalized_value='1.5',operator=op)
            c['result']=result
            if result=='no_signal': d['findings']=[]
            self.assertTrue(self.check(d)['schema_valid'],self.check(d))

    def test_non_finite_or_boolean_numbers_are_rejected(self):
        for value in ['NaN','Infinity',True]:
            d=sample(); d['checks'][0]['comparison']['observed_value']=value
            self.assertInvalid(d,'finite decimal')

    def test_draft_rule_cannot_be_presented_as_evaluated(self):
        d=sample(); d['rules'][0]['status']='draft'
        self.assertInvalid(d,'requires a verified')

    def test_unknown_basis_requires_abstention(self):
        d=sample(); d['bases'][0]['status']='unknown'
        self.assertInvalid(d,'unverified')

    def test_abstaining_draft_does_not_need_invented_basis_metadata(self):
        d=sample(); b=d['bases'][0]
        b.update(kind='standard',status='unknown',authority='unknown',applicability='unknown',
                 identifier=None,clause=None,source_ref=None,verified_by=None,verified_at=None,rights_basis=None)
        d['rules'][0]['status']='draft'
        d['rules'][0]['applicability']['state']='unknown'
        d['rules'][0]['criterion'].update(basis_locator=None,threshold=None,unit=None,operator=None)
        d['checks'][0].update(status='unverified_basis',result=None,comparison=None,reason='Official clause could not be verified')
        d['findings']=[]
        r=self.check(d)
        self.assertTrue(r['schema_valid'],r)
        self.assertEqual(r['signoff_readiness'],'blocked')
        self.assertIn('未核验',render(d,r))

    def test_malformed_operator_is_reported_without_traceback(self):
        for op in [[],{}]:
            d=sample(); d['checks'][0]['comparison']['operator']=op
            self.assertInvalid(d,'differs from rule')

    def test_unreadable_source_cannot_claim_evaluated(self):
        d=sample(); d['sources'][0]['capability']='unreadable'
        self.assertInvalid(d,'unreadable source')

    def test_synthetic_standard_cannot_enter_real_project(self):
        d=sample(); d['mode']='project'
        self.assertInvalid(d,'synthetic basis')

    def test_expired_basis_without_transition_is_rejected(self):
        d=sample(); b=d['bases'][0]
        b.update(kind='standard',status='superseded',authority='official',effective_from='2020-01-01',effective_to='2025-01-01',transition_ref=None)
        self.assertInvalid(d,'unverified')

    def test_explicit_project_transition_record_can_be_used(self):
        d=sample(); b=d['bases'][0]
        b.update(kind='standard',status='superseded',authority='official',effective_from='2020-01-01',effective_to='2025-01-01',transition_ref='EX-synthetic transition record; not an actual regulation')
        self.assertTrue(self.check(d)['schema_valid'],self.check(d))

    def test_undetermined_never_closes_the_issue(self):
        d=sample(True); f=d['findings'][0]
        f['review']['status']='undetermined'; f['closure']['status']='open'
        r=self.check(d)
        self.assertTrue(r['schema_valid'],r)
        self.assertEqual(r['signoff_readiness'],'blocked')

    def test_reply_only_never_closes_the_issue(self):
        d=sample(True); d['findings'][0]['closure']['status']='response_submitted'
        r=self.check(d)
        self.assertTrue(r['schema_valid'],r)
        self.assertEqual(r['signoff_readiness'],'blocked')

    def test_old_baseline_recheck_is_rejected(self):
        d=sample(True); d['findings'][0]['closure']['recheck']['baseline_id']='OLD'
        self.assertInvalid(d,'different baseline')

    def test_missing_recheck_record_or_actor_cannot_close(self):
        for key in ['actor','record_ref']:
            d=sample(True); del d['findings'][0]['closure']['recheck'][key]
            self.assertInvalid(d,key)

    def test_not_applicable_requires_current_human_record(self):
        d=sample(True); f=d['findings'][0]
        f['review']['status']='not_applicable'
        f['closure']['status']='not_applicable'
        self.assertInvalid(d,'current baseline')
        f['review']['baseline_id']=d['project']['baseline_id']
        self.assertTrue(self.check(d)['schema_valid'],self.check(d))

    def test_approved_enum_is_not_a_substitute_for_review(self):
        d=sample(True); d['findings'][0]['review']['status']='approved'
        self.assertInvalid(d,'review.status')

    def test_restricted_cloud_path_is_rejected(self):
        d=sample(True)
        d['project']['data_class']='restricted'; d['project']['processing']['mode']='cloud'
        self.assertInvalid(d,'cannot be routed to cloud')

    def test_internal_cloud_needs_explicit_records(self):
        d=sample(True)
        d['project']['data_class']='internal'; d['project']['processing']['mode']='cloud'
        self.assertInvalid(d,'sanitization')
        d['project']['processing'].update(authorization_ref='EX-scoped authorization',sanitization_ref='EX-sanitization')
        self.assertEqual(self.check(d)['signoff_readiness'],'ready_for_human_signoff')

    def test_missing_environment_verification_blocks_ready(self):
        d=sample(True); d['project']['processing']['environment_verified']=False
        r=self.check(d)
        self.assertTrue(r['schema_valid'],r)
        self.assertEqual(r['signoff_readiness'],'blocked')

    def test_duplicate_ids_and_unknown_refs_are_rejected(self):
        d=sample(); d['sources'].append(copy.deepcopy(d['sources'][0]))
        self.assertInvalid(d,'duplicate ID')
        d=sample(); d['checks'][0]['rule_id']='UNKNOWN'
        self.assertInvalid(d,'unknown rule_id')

    def test_conflict_requires_two_distinct_sources(self):
        d=sample(); d['findings'][0]['kind']='document_conflict'
        self.assertInvalid(d,'two distinct')

    def test_future_human_timestamp_is_rejected(self):
        d=sample(True); d['findings'][0]['review']['at']='2099-01-01T10:00:00+08:00'
        self.assertInvalid(d,'timestamp')

    def test_report_marks_synthetic_and_keeps_unresolved_items(self):
        d=sample(); report=render(d,self.check(d))
        self.assertIn('合成演示',report)
        self.assertIn('F-EX-001',report)
        self.assertIn('存在阻塞',report)
        self.assertIn('不能证明整体设计通过',report)

    def test_out_of_root_sources_are_rejected(self):
        d=sample(); d['sources'][0]['path']='../SKILL.md'
        self.assertInvalid(d,'escapes the authorized root')

    def test_link_source_outside_root_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root'; root.mkdir()
            outside=Path(tmp)/'outside'; outside.mkdir(); (outside/'other.txt').write_text('outside',encoding='utf-8')
            make_link(root/'linked',outside)
            d=sample(); d['sources'][0]['path']='linked/other.txt'
            r=self.check(d,root=root)
            self.assertFalse(r['schema_valid'])
            self.assertTrue(any('escapes' in e for e in r['errors']))

    def test_malformed_container_reports_errors_without_traceback(self):
        for d in [[],{}, {'schema_version':'1.0','project':[]},
                  {**sample(),'checks':[None]}, {**sample(),'bases':[{'id':'BAS-EX-01','status':[]}]}]:
            r=self.check(d)
            self.assertFalse(r['schema_valid'])

class ToolChecks(unittest.TestCase):
    def test_inventory_skips_links_that_leave_the_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'root'; root.mkdir(); (root/'sheet.txt').write_bytes(b'123')
            (root/'.secret.txt').write_text('private metadata')
            outside=Path(tmp)/'outside'; outside.mkdir(); (outside/'secret.txt').write_bytes(b'outside')
            make_link(root/'linked',outside)
            result=inventory(root)
            self.assertEqual([item['path'] for item in result['files']],['sheet.txt'])
            self.assertEqual(result['files'][0]['sha256'],'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3')
            self.assertEqual([item['path'] for item in result['skipped']],['linked'])
            self.assertIn(result['skipped'][0]['reason'],{'symlink','outside_root'})

    def test_cli_gate_exit_codes(self):
        for filename,expected in [('example-review.json',3),('example-complete.json',0)]:
            r=subprocess.run([sys.executable,str(HERE/'validate_review.py'),str(ASSETS/filename),'--gate'],capture_output=True,text=True)
            self.assertEqual(r.returncode,expected,r.stdout+r.stderr)

    def test_report_output_collision_preserves_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'report.md'; output.write_text('original')
            r=subprocess.run([sys.executable,str(HERE/'render_report.py'),str(ASSETS/'example-review.json'),'--output',str(output)],capture_output=True,text=True)
            self.assertEqual(r.returncode,2)
            self.assertEqual(output.read_text(),'original')

    @unittest.skipUnless((BUNDLE/'install.py').is_file(),'Installer is supplied in the complete bundle, not each installed skill')
    def test_installer_stops_before_mutation_on_any_collision(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=Path(tmp); existing=target/'aia-fire'; existing.mkdir()
            (existing/'keep.txt').write_text('original')
            r=subprocess.run([sys.executable,str(BUNDLE/'install.py'),'--target',str(target)],capture_output=True,text=True)
            self.assertEqual(r.returncode,2)
            self.assertEqual([p.name for p in target.iterdir()],['aia-fire'])
            self.assertEqual((existing/'keep.txt').read_text(),'original')

if __name__=='__main__':
    unittest.main(verbosity=2)
