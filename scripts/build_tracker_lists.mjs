#!/usr/bin/env node
// Builds extension/data/tracker-lists.json from the bundled list snapshots.
//
//   node scripts/build_tracker_lists.mjs            # offline: recompile snapshots in data/blocklists/
//   node scripts/build_tracker_lists.mjs --refresh  # download fresh snapshots first (the ONLY place the lists are fetched)
//
// The extension never downloads lists at runtime; refresh, review the diff, commit.
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parseFilterList, parseHeader, serializeCompiled } from "./lib/parse-filters.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SNAP_DIR = path.join(ROOT, "data", "blocklists");
const MANIFEST = path.join(SNAP_DIR, "manifest.json");
const OUT = path.join(ROOT, "extension", "data", "tracker-lists.json");

const LISTS = [
  { name: "easylist", file: "easylist.txt", source: "https://easylist.to/easylist/easylist.txt",
    purpose: "ads and ad-tech" },
  { name: "easyprivacy", file: "easyprivacy.txt", source: "https://easylist.to/easylist/easyprivacy.txt",
    purpose: "trackers, analytics, fingerprinting" },
];
const LICENSE = "GPLv3+ / CC BY-SA 3.0 (dual-licensed by the EasyList authors)";

const refresh = process.argv.includes("--refresh");
const prev = fs.existsSync(MANIFEST) ? JSON.parse(fs.readFileSync(MANIFEST, "utf8")) : { lists: [] };
const today = new Date().toISOString().slice(0, 10);

fs.mkdirSync(SNAP_DIR, { recursive: true });
fs.mkdirSync(path.dirname(OUT), { recursive: true });

const manifest = { generated_utc: new Date().toISOString(), license: LICENSE, lists: [] };
const compiledOut = {};

for (const l of LISTS) {
  const file = path.join(SNAP_DIR, l.file);
  if (refresh) {
    const res = await fetch(l.source);
    if (!res.ok) throw new Error(`${l.source} -> HTTP ${res.status}`);
    fs.writeFileSync(file, Buffer.from(await res.arrayBuffer()));
  }
  const buf = fs.readFileSync(file);
  const text = buf.toString("utf8");
  const header = parseHeader(text);
  const { compiled, stats } = parseFilterList(text);
  const old = prev.lists.find((x) => x.name === l.name);
  manifest.lists.push({
    name: l.name,
    purpose: l.purpose,
    source: l.source,
    downloaded: refresh ? today : old?.downloaded ?? null,
    list_version: header.version,
    last_modified: header.last_modified,
    bytes: buf.length,
    sha256: createHash("sha256").update(buf).digest("hex"),
    rules_compiled: stats.compiled,
    rules_skipped: stats.skipped,
  });
  compiledOut[l.name] = serializeCompiled(compiled);
  console.log(`${l.name}: version ${header.version}, compiled ${stats.compiled} rules `
    + `(${compiled.domains.size} domains, ${[...compiled.paths.values()].reduce((n, s) => n + s.size, 0)} path rules, `
    + `${compiled.exceptions.size} exceptions); skipped ${JSON.stringify(stats.skipped)}`);
}

fs.writeFileSync(MANIFEST, JSON.stringify(manifest, null, 2) + "\n");
fs.writeFileSync(OUT, JSON.stringify({ meta: manifest, ...compiledOut }));
console.log(`wrote ${path.relative(ROOT, MANIFEST)} and ${path.relative(ROOT, OUT)} (${(fs.statSync(OUT).size / 1048576).toFixed(2)} MB)`);
