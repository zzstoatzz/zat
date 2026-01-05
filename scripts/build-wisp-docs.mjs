import {
  readdir,
  readFile,
  mkdir,
  rm,
  cp,
  writeFile,
  access,
} from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const repoRoot = path.resolve(new URL("..", import.meta.url).pathname);
const docsDir = path.join(repoRoot, "docs");
const siteSrcDir = path.join(repoRoot, "site");
const outDir = path.join(repoRoot, "site-out");
const outDocsDir = path.join(outDir, "docs");

const execFileAsync = promisify(execFile);

async function exists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

function isMarkdown(filePath) {
  return filePath.toLowerCase().endsWith(".md");
}

async function listMarkdownFiles(dir, prefix = "") {
  const entries = await readdir(dir, { withFileTypes: true });
  const out = [];
  for (const e of entries) {
    if (e.name.startsWith(".")) continue;
    const rel = path.join(prefix, e.name);
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) {
      out.push(...(await listMarkdownFiles(abs, rel)));
    } else if (e.isFile() && isMarkdown(e.name)) {
      out.push(rel.replaceAll(path.sep, "/"));
    }
  }
  return out.sort((a, b) => a.localeCompare(b));
}

function titleFromMarkdown(md, fallback) {
  const lines = md.split(/\r?\n/);
  for (const line of lines) {
    const m = /^#\s+(.+)\s*$/.exec(line);
    if (m) return m[1].trim();
  }
  return fallback.replace(/\.md$/i, "");
}

async function getBuildId() {
  try {
    const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
    });
    const full = String(stdout || "").trim();
    if (full) return full.slice(0, 12);
  } catch {
    // ignore
  }
  return String(Date.now());
}

async function main() {
  await rm(outDir, { recursive: true, force: true });
  await mkdir(outDir, { recursive: true });

  // Copy static site shell
  await cp(siteSrcDir, outDir, { recursive: true });

  // Cache-bust immutable assets on Wisp by appending a per-commit query string.
  const buildId = await getBuildId();
  const outIndex = path.join(outDir, "index.html");
  if (await exists(outIndex)) {
    let html = await readFile(outIndex, "utf8");
    html = html.replaceAll('href="./style.css"', `href="./style.css?v=${buildId}"`);
    html = html.replaceAll(
      'src="./vendor/marked.min.js"',
      `src="./vendor/marked.min.js?v=${buildId}"`,
    );
    html = html.replaceAll(
      'src="./app.js"',
      `src="./app.js?v=${buildId}"`,
    );
    html = html.replaceAll(
      'href="./favicon.svg"',
      `href="./favicon.svg?v=${buildId}"`,
    );
    await writeFile(outIndex, html, "utf8");
  }

  // Copy docs
  await mkdir(outDocsDir, { recursive: true });

  const pages = [];

  // Prefer an explicit docs homepage if present; otherwise use repo README as index.
  const docsIndex = path.join(docsDir, "index.md");
  if (!(await exists(docsIndex))) {
    const readme = path.join(repoRoot, "README.md");
    if (await exists(readme)) {
      const md = await readFile(readme, "utf8");
      await writeFile(path.join(outDocsDir, "index.md"), md, "utf8");
      pages.push({ path: "index.md", title: titleFromMarkdown(md, "index.md") });
    }
  }

  const changelog = path.join(repoRoot, "CHANGELOG.md");
  const docsChangelog = path.join(docsDir, "changelog.md");
  if ((await exists(changelog)) && !(await exists(docsChangelog))) {
    const md = await readFile(changelog, "utf8");
    await writeFile(path.join(outDocsDir, "changelog.md"), md, "utf8");
    pages.push({
      path: "changelog.md",
      title: titleFromMarkdown(md, "changelog.md"),
    });
  }

  const mdFiles = (await exists(docsDir)) ? await listMarkdownFiles(docsDir) : [];

  for (const rel of mdFiles) {
    const src = path.join(docsDir, rel);
    const dst = path.join(outDocsDir, rel);
    await mkdir(path.dirname(dst), { recursive: true });
    await cp(src, dst);

    const md = await readFile(src, "utf8");
    pages.push({ path: rel, title: titleFromMarkdown(md, rel) });
  }

  await writeFile(
    path.join(outDir, "manifest.json"),
    JSON.stringify({ pages }, null, 2) + "\n",
    "utf8",
  );

  process.stdout.write(
    `Built Wisp docs site: ${pages.length} markdown file(s) -> ${outDir}\n`,
  );
}

await main();
