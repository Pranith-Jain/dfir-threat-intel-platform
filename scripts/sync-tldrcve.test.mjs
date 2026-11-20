/** Offline parser tests for the tldrcve.com replication. */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decodeEntities, parseCveList, parseDetail, parseVersions, text } from './sync-tldrcve.mjs';

const LIST_HTML = `<main><ol class="rows">
  <li class="row" data-search="php2shell php cve-2026-109618" data-scare="3.9" data-disclosed="2026-10-21">
    <a href="/php2shell/">
      <span class="row__meter"><span class="mini-meter" data-level="4" role="img" aria-label="Scare-o-meter: Drop everything"></span></span>
      <span class="row__main"><span class="row__name">PHP2Shell</span><span class="row__meta">PHP &middot; CVE-2026-109618</span></span>
      <span class="row__line">Exploited in the wild. In CISA KEV.</span>
      <span class="row__verdict"><span class="verdict verdict--now">Patch now</span></span>
      <time class="row__date">21 Oct</time>
    </a>
  </li>
</ol></main>`;

const VERSION_HTML = `<main><ul class="vcards">
  <li class="vcard" data-search="dotnet .net 11.0.0" data-nofix="0"><a href="/versions/dotnet/">
    <span class="vcard__top"><span class="vcard__name">.NET</span><span class="vcard__meta">1 bug &middot; checked 20 Nov</span></span>
    <span class="vchips"><span class="vchip"><span>11</span><b>11.0.0</b></span><span class="vchip"><span>10</span><b>10.0.15</b></span></span>
  </a></li>
</ul></main>`;

const DETAIL_HTML = `<main>
  <header class="brief-head">
    <p class="kicker">PHP &middot; CVE-2026-129289</p><h1>PHP-FPM smuggling</h1>
    <p class="verdict-line"><span class="verdict verdict--if">Patch now if&hellip;</span><span>Only if FastCGI connections are reused</span></p>
    <p class="summary">A bug in PHP-FPM can let an attacker run code.</p>
  </header>
  <section class="pane" aria-labelledby="h-scare">
    <div class="scare">
      <ul class="checklist">
        <li class="check check--yes"><span class="check__box">&#10003;</span><span class="visually-hidden">Yes: </span><span>Works without logging in</span></li>
        <li class="check check--no"><span class="check__box"></span><span class="visually-hidden">No: </span><span>No attacks seen yet</span></li>
      </ul>
      <div class="meter"><p class="meter__name">Scare-o-meter</p><p class="meter__label">Check today</p><p class="meter__hint">Find out if you are affected.</p></div>
    </div>
  </section>
  <section class="pane" aria-labelledby="h-affected"><details class="fold">
    <summary><span class="fold__num">1</span><span class="fold__title">PHP-FPM older than the fix</span><span class="fold__hint">command</span></summary>
    <div class="fold__body"><p>Below 8.5.13.</p><pre><code>php-fpm -v</code></pre></div>
  </details></section>
  <section class="pane" aria-labelledby="h-do"><details class="fold">
    <summary><span class="fold__num">1</span><span class="fold__title">Upgrade PHP</span></summary>
    <div class="fold__body"><p>Install the fixed release.</p></div>
  </details></section>
  <details class="sources-fold" id="sources"><summary>Sources (1)</summary><ol class="sources">
    <li><a href="https://php.net/changelog">PHP changelog</a> <span class="src-date">19 Nov</span></li>
  </ol><ul class="changes"><li><time datetime="2026-11-20">20 Nov</time><span>Published.</span></li></ul></details>
</main>`;

test('decodeEntities and text strip markup and entities', () => {
  assert.equal(text('<b>A &amp; B</b> &middot; C'), 'A & B · C');
  assert.equal(decodeEntities('&#x27;quoted&#x27;'), "'quoted'");
});

test('parseCveList reads rows with scare score, verdict and upstream URL', () => {
  const rows = parseCveList(LIST_HTML);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].slug, 'php2shell');
  assert.equal(rows[0].name, 'PHP2Shell');
  assert.equal(rows[0].scareLevel, 3.9);
  assert.equal(rows[0].meterLabel, 'Drop everything');
  assert.equal(rows[0].verdict, 'Patch now');
  assert.equal(rows[0].url, 'https://tldrcve.com/php2shell/');
});

test('parseVersions reads version chips and no-fix flag', () => {
  const rows = parseVersions(VERSION_HTML);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].name, '.NET');
  assert.equal(rows[0].nofix, false);
  assert.deepEqual(rows[0].chips.map((c) => c.version), ['11.0.0', '10.0.15']);
});

test('parseDetail splits scare, affected, actions, sources and changelog', () => {
  const d = parseDetail(DETAIL_HTML, 'php-fpm-smuggling');
  assert.equal(d.name, 'PHP-FPM smuggling');
  assert.equal(d.verdict, 'Patch now if…');
  assert.equal(d.meterLabel, 'Check today');
  assert.equal(d.checklist.length, 2);
  assert.equal(d.checklist[0].yes, true);
  assert.equal(d.affected.length, 1);
  assert.deepEqual(d.affected[0].code, ['php-fpm -v']);
  assert.equal(d.actions.length, 1);
  assert.equal(d.sources[0].date, '19 Nov');
  assert.equal(d.changes[0].text, 'Published.');
});

test('parsers degrade to empty arrays on missing markup', () => {
  assert.deepEqual(parseCveList(''), []);
  assert.deepEqual(parseVersions(''), []);
  const d = parseDetail('', 'x');
  assert.deepEqual(d.affected, []);
  assert.deepEqual(d.sources, []);
});
