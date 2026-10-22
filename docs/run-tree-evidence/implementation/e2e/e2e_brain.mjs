// Outside-the-process consumer: the Brain's REAL runEventsBatch (delphi-sentinel
// feat/run-tree-reader) ingesting the JSONL a separate sensor process wrote.
// The database is a capturing fake (DB access is blocked on purpose); every
// insert row is printed and checked.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
// Same placeholders the Brain's own test uses; nothing here reaches a network.
process.env.SUPABASE_URL ||= 'https://placeholder.supabase.co';
process.env.SUPABASE_SERVICE_KEY ||= 'placeholder-service-key';
const { runEventsBatch } = await import('/Users/anirudhkotaru/worktrees/delphi-sentinel/run-tree-reader/src/events-batch.ts');
const calls = { inserts: [] };
function builder(table) {
  let op = 'select';
  const b = {
    select() { op = 'select'; return b; }, insert(row) { op = 'insert'; calls.inserts.push({ table, row }); return b; },
    update() { return b; }, upsert() { return b; }, delete() { return b; }, eq() { return b; }, gte() { return b; },
    gt() { return b; }, lt() { return b; }, in() { return b; }, or() { return b; }, not() { return b; },
    order() { return b; }, limit() { return b; },
    maybeSingle() { return Promise.resolve({ data: table === 'agent_registry' ? { status: 'active' } : null, error: null }); },
    single() { return b.maybeSingle(); },
    then(res, rej) { return Promise.resolve(op === 'select' ? { data: null, error: null } : { error: null }).then(res, rej); },
  };
  return b;
}
const deps = { supabase: { from: builder, rpc: () => Promise.resolve({ error: null }) },
  runCorrelation: async () => {}, log: { info() {}, warn: (m) => console.log('WARN', m), error: (m) => console.log('ERR', m) } };
const events = readFileSync(process.argv[2], 'utf8').trim().split('\n').map((l) => JSON.parse(l));
const result = await runEventsBatch({ events, auth: { deploymentId: 'd1', userId: 'u1' } }, deps);
const rows = calls.inserts.filter((i) => i.table === 'ai_guard_logs').map((i) => i.row);
console.log('events in', events.length, '| ai_guard_logs rows', rows.length,
  '| runRootRejected', result.runRootRejected, '| traceParentRejected', result.traceParentRejected);
for (const [i, r] of rows.entries()) {
  const d = events[i].data, md = r.metadata;
  console.log([r.scan_mode, md.toolName, md.runTree, (r.run_root_id || 'NULL').slice(-12), JSON.stringify(md.runNodePath),
    md.runSeq, md.toolCallId, r.trace_id || 'NULL', md.traceSource || '-'].join(' | '));
  assert.equal(r.run_root_id, d.runTree === 'stamped' ? d.runRootId : null, 'run_root_id does not match the sensor');
  if (d.traceParent) assert.equal(r.trace_id, '00-' + d.traceParent.traceId + '-' + d.traceParent.spanId + '-' + d.traceParent.traceFlags);
}
const roots = new Set(rows.filter((r) => r.run_root_id).map((r) => r.run_root_id));
console.log('distinct run_root_id:', roots.size, '| rows with trace_id:', rows.filter((r) => r.trace_id).length,
  '| no_run rows with a root:', rows.filter((r) => r.metadata.runTree === 'no_run' && r.run_root_id).length);
assert.equal(roots.size, 2); console.log('E2E BRAIN INGEST: OK');
