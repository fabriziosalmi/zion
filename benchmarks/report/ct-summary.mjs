// Classify a cache-tests CLI result file with the suite's own functions.
//   node ct-summary.mjs <cache-tests dir> <results.json>   → one JSON object on stdout
// A test counts as passed when the suite itself says pass; "optional_fail" is the suite's
// word for a failed optional behaviour and is counted apart, as is every other outcome.
import { pathToFileURL } from 'node:url'
import { readFileSync } from 'node:fs'

const [dir, file] = process.argv.slice(2)
const { default: tests } = await import(pathToFileURL(`${dir}/tests/index.mjs`).href)
const { determineTestResult, resultTypes } = await import(pathToFileURL(`${dir}/test-engine/lib/results.mjs`).href)
const results = JSON.parse(readFileSync(file, 'utf8'))
const name = new Map(Object.entries(resultTypes).map(([k, v]) => [v, k]))

const out = { tests: 0, outcomes: {}, suites: {}, failed: [] }
for (const suite of tests) {
  const s = (out.suites[suite.name] = { tests: 0, passed: 0, failed: 0 })
  for (const t of suite.tests) {
    const kind = name.get(determineTestResult(tests, t.id, results, false)) || 'unknown'
    out.tests++; s.tests++
    out.outcomes[kind] = (out.outcomes[kind] || 0) + 1
    if (kind === 'pass' || kind === 'yes') s.passed++
    else if (kind === 'fail') { s.failed++; out.failed.push(`${suite.name}: ${t.name} [${t.id}]`) }
  }
}
out.passed = (out.outcomes.pass || 0) + (out.outcomes.yes || 0)
out.failed_count = out.outcomes.fail || 0
console.log(JSON.stringify(out))
