// Test cases for child-process.yaml, run with `semgrep --test`. Not app code.
import { exec, execSync } from 'node:child_process'
const cp = require('child_process')

export function cases (req: any) {
  // ruleid: gate.child-process-exec-nonliteral
  exec(`ping -c 1 ${req.query.host}`, () => {})
  // ruleid: gate.child-process-exec-nonliteral
  execSync('ls ' + req.query.dir)
  // ruleid: gate.child-process-exec-nonliteral
  cp.exec(req.body.cmd)
  // ok: gate.child-process-exec-nonliteral
  exec('uptime', () => {})
  // ok: gate.child-process-exec-nonliteral
  cp.execSync('date')
}
