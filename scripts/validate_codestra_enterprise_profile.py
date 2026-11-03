#!/usr/bin/env python3
import json,os,pathlib,sys
HOST='cadv.codestra.media'
def fail(m): print('ERROR: '+m,file=sys.stderr); raise SystemExit(1)
p=pathlib.Path('codestra/enterprise-profile.v1.json')
if not p.exists(): fail('missing enterprise profile')
d=json.loads(p.read_text())
if d.get('canonicalHostname')!=HOST: fail('wrong canonical hostname')
if d.get('schemaVersion')!='1.0' or d.get('status')!='SOURCE_PREPARED_NOT_DEPLOYED': fail('invalid schema/status')
if not d.get('containerMetricScope') or not d.get('features'): fail('container metrics/features must be defined')
if d.get('exposure')=='public_native': fail('native service may not be public')
print('Codestra enterprise profile validation PASS: '+os.environ.get('GITHUB_REPOSITORY','cadvisor'))
