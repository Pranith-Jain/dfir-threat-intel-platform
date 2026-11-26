/** Offline parser tests for the PromptIntel IoPC taxonomy mirror. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeEntities, parseEntryPage, parseFrameworks, parseTaxonomyIndex, text } from './sync-promptintel.mjs';

const INDEX = `
<h1>IoPC Taxonomy</h1>
<p>IoPC (Indicators of Prompt Compromise) is an open, versioned classification. Version 2.2.0.</p>
<h2>T1 Instruction &amp; Input Injection</h2>
<p>Techniques that introduce attacker-controlled instructions.</p>
<ul>
<li><a href="/taxonomy/IOPC-T1.001/"><strong>IOPC-T1.001</strong> Direct Prompt Injection</a>: Attacker-authored instructions supplied directly in the user-controlled input channel.</li>
<li><a href="/taxonomy/IOPC-T1.002/"><strong>IOPC-T1.002</strong> Indirect Prompt Injection</a>: Attacker instructions embedded in third-party content.</li>
</ul>
<h2>T2 Data, Retrieval &amp; Memory Poisoning</h2>
<p>Techniques that corrupt the data an AI system retrieves.</p>
<ul>
<li><a href="/taxonomy/IOPC-T2.001/"><strong>IOPC-T2.001</strong> Retrieval / RAG Poisoning</a>: Malicious content placed in a knowledge source.</li>
</ul>
`;

const ENTRY = `
<nav><a href="/taxonomy">IoPC taxonomy</a></nav>
<h1>IOPC-T1.001 Direct Prompt Injection</h1>
<p>Attacker-authored instructions supplied directly in the user-controlled input channel to override system or developer intent.</p>
<h2>How it differs</h2><p>Canonical form of registry entry IOPC-R001.</p>
<h2>Status</h2>
<p>active, evidence: mixed, reviewed 2026-11-12.</p>
<h2>Mapped to</h2>
<ul>
<li>CSA Autonomous Action Runtime Management (AARM): <strong>T1</strong> Prompt Injection (related)</li>
<li>Google Secure AI Framework (SAIF): <strong>control:Input Validation and Sanitization</strong> Input Validation and Sanitization (control relevant)</li>
<li>MITRE ATLAS: <strong>AML.T0051.000</strong> LLM Prompt Injection: Direct (equivalent)</li>
<li>OWASP Top 10 for LLM Applications: <strong>LLM01</strong> Prompt Injection (narrower than)</li>
</ul>
<p>PromptIntel is a product by <a href="https://securitybreak.io">SecurityBreak</a>.</p>
`;

const FRAMEWORKS = `
<h1>Framework mappings</h1>
<p>Look up any framework item.</p>
<ul>
<li><strong>OWASP Top 10 for LLM Applications</strong> (version 2026): <a href="https://genai.owasp.org/llm-top-10/" rel="noopener">https://genai.owasp.org/llm-top-10/</a></li>
<li><strong>MITRE ATLAS</strong> (version 2026.10): <a href="https://atlas.mitre.org/" rel="noopener">https://atlas.mitre.org/</a></li>
</ul>
<p>The mappings are also available from the API.</p>
`;

test('text() strips tags, decodes entities and collapses whitespace', () => {
  assert.equal(text('<p>Data &amp; <strong>Retrieval</strong></p>'), 'Data & Retrieval');
  assert.equal(decodeEntities('Prompt&nbsp;Injection &mdash; &#65;'), 'Prompt Injection — A');
});

test('parseTaxonomyIndex reads the version, domains and techniques', () => {
  const { version, domains, entries } = parseTaxonomyIndex(INDEX);
  assert.equal(version, '2.2.0');
  assert.equal(domains.length, 2);
  assert.equal(domains[0].id, 'T1');
  assert.equal(domains[0].name, 'Instruction & Input Injection');
  assert.deepEqual(domains[0].techniques, ['IOPC-T1.001', 'IOPC-T1.002']);
  assert.equal(entries.length, 3);
  assert.equal(entries[0].name, 'Direct Prompt Injection');
  assert.equal(entries[0].domain, 'T1');
  assert.match(entries[0].summary, /Attacker-authored/);
  assert.equal(entries[2].url, 'https://promptintel.securitybreak.io/taxonomy/IOPC-T2.001/');
});

test('parseTaxonomyIndex ignores nav links without a technique id', () => {
  const { entries } = parseTaxonomyIndex('<h2>T9 Persistence</h2><ul><li><a href="/taxonomy">All</a></li></ul>');
  assert.equal(entries.length, 0);
});

test('parseEntryPage pulls description, status and every mapping row', () => {
  const entry = parseEntryPage(ENTRY, 'IOPC-T1.001');
  assert.equal(entry.name, 'Direct Prompt Injection');
  assert.match(entry.description, /user-controlled input channel/);
  assert.match(entry.differs, /IOPC-R001/);
  assert.equal(entry.maturity, 'active');
  assert.equal(entry.evidence, 'mixed');
  assert.equal(entry.reviewed, '2026-11-12');
  assert.equal(entry.mappings.length, 4);
  assert.deepEqual(entry.mappings[0], {
    framework: 'CSA Autonomous Action Runtime Management (AARM)',
    ref: 'T1',
    name: 'Prompt Injection',
    relationship: 'related',
  });
  assert.equal(entry.mappings[1].ref, 'control:Input Validation and Sanitization');
  assert.equal(entry.mappings[1].relationship, 'control relevant');
  assert.equal(entry.mappings[2].name, 'LLM Prompt Injection: Direct');
  assert.equal(entry.mappings[3].ref, 'LLM01');
});

test('parseEntryPage never leaks the footer boilerplate into the body', () => {
  const entry = parseEntryPage(ENTRY, 'IOPC-T1.001');
  assert.doesNotMatch(entry.differs, /SecurityBreak/);
  assert.doesNotMatch(entry.description, /SecurityBreak/);
});

test('parseFrameworks reads name, version and upstream url', () => {
  const frameworks = parseFrameworks(FRAMEWORKS);
  assert.equal(frameworks.length, 2);
  assert.deepEqual(frameworks[0], {
    name: 'OWASP Top 10 for LLM Applications',
    version: '2026',
    url: 'https://genai.owasp.org/llm-top-10/',
  });
  assert.equal(frameworks[1].version, '2026.10');
});

test('parseEntryPage survives a page with no mapping table', () => {
  const entry = parseEntryPage('<h1>IOPC-T9.009 Example</h1><p>Only a description.</p>', 'IOPC-T9.009');
  assert.equal(entry.name, 'Example');
  assert.equal(entry.maturity, 'unknown');
  assert.equal(entry.reviewed, null);
  assert.deepEqual(entry.mappings, []);
});
