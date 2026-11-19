import test from "node:test";
import assert from "node:assert/strict";
import worker from "../src/preview-apt.js";

function makeEnv(objects = {}) {
  const requested = [];
  return {
    requested,
    PREVIEW: {
      async get(key) {
        requested.push(key);
        const body = objects[key];
        return body === undefined ? null : {
          body: new TextEncoder().encode(body),
          size: new TextEncoder().encode(body).byteLength,
          etag: "test-etag",
          uploaded: new Date("2026-11-19T00:00:00Z"),
        };
      },
    },
  };
}

test("serves only the preview Focal release metadata and smoke package namespace", async () => {
  const repositoryRoot = "/runs/321/2";
  const allowed = [
    "/dists/focal/InRelease",
    "/dists/focal/Release",
    "/dists/focal/Release.gpg",
    "/dists/focal/main/binary-amd64/Packages.gz",
    "/dists/focal/main/source/Sources.xz",
    "/pool/main/g/getpatched-preview-smoke/getpatched-preview-smoke_0.1.0+preview1_all.deb",
    "/pool/main/g/getpatched-preview-smoke/getpatched-preview-smoke_0.1.0+preview1.dsc",
    "/pool/main/g/getpatched-preview-smoke/getpatched-preview-smoke_0.1.0+preview1.tar.xz",
    "/getpatched-preview-archive-keyring.asc",
  ];
  const objects = Object.fromEntries(allowed.map((path) => [`runs/321/2${path}`, "preview object"]));
  const env = makeEnv(objects);
  for (const path of allowed) {
    const response = await worker.fetch(new Request(`https://preview.getpatched.dev${repositoryRoot}${path}`), env);
    assert.notEqual(response.status, 404, path);
  }
  assert.equal(env.requested.length, allowed.length);
  assert.ok(env.requested.every((key) => key.startsWith("runs/321/2/dists/focal/") || key.startsWith("runs/321/2/pool/main/g/getpatched-preview-smoke/") || key.endsWith("archive-keyring.asc")));
});

test("rejects other hosts, paths, encoded paths, and write methods without reading storage", async () => {
  const env = makeEnv({ "runs/321/2/dists/focal/InRelease": "signed-release" });
  for (const request of [
    new Request("https://repo.getpatched.dev/dists/focal/InRelease"),
    new Request("https://preview.getpatched.dev/dists/jammy/InRelease"),
    new Request("https://preview.getpatched.dev/internal/repository-snapshots/public"),
    new Request("https://preview.getpatched.dev/pool/main/g/getpatched-preview-smoke/other.deb"),
    new Request("https://preview.getpatched.dev/runs/0/1/dists/focal/InRelease"),
    new Request("https://preview.getpatched.dev/runs/321/02/dists/focal/InRelease"),
    new Request("https://preview.getpatched.dev/%2e%2e/internal"),
    new Request("https://preview.getpatched.dev/runs/321/2/dists/focal/InRelease", { method: "PUT" }),
  ]) {
    const response = await worker.fetch(request, env);
    assert.ok(response.status === 404 || response.status === 405, `${request.url}: ${response.status}`);
  }
  assert.deepEqual(env.requested, []);
});

test("supports HEAD and serves metadata without cache while package files are immutable", async () => {
  const env = makeEnv({ "runs/321/2/dists/focal/InRelease": "signed-release" });
  const head = await worker.fetch(new Request("https://preview.getpatched.dev/runs/321/2/dists/focal/InRelease", { method: "HEAD" }), env);
  assert.equal(head.status, 200);
  assert.equal(head.headers.get("cache-control"), "no-cache, max-age=0, must-revalidate");
  assert.equal(await head.text(), "");

  const health = await worker.fetch(new Request("https://preview.getpatched.dev/healthz"), env);
  assert.equal(health.status, 200);
  assert.equal((await health.json()).readOnly, true);
});
