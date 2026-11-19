const PACKAGE_DIRECTORY = "pool/main/g/getpatched-preview-smoke/";
const PACKAGE_FILE = /^getpatched-preview-smoke_[0-9][A-Za-z0-9.+~:-]*(?:_(?:all|amd64)\.deb|\.dsc|\.tar\.xz)$/;
const INDEX_FILES = new Set([
  "dists/focal/InRelease",
  "dists/focal/Release",
  "dists/focal/Release.gpg",
  "dists/focal/main/binary-amd64/Packages",
  "dists/focal/main/binary-amd64/Packages.gz",
  "dists/focal/main/binary-amd64/Packages.xz",
  "dists/focal/main/source/Sources",
  "dists/focal/main/source/Sources.gz",
  "dists/focal/main/source/Sources.xz",
]);

function publicPath(path) {
  const relativePath = path.startsWith("/") ? path.slice(1) : path;
  const match = /^runs\/([1-9][0-9]*)\/([1-9][0-9]*)\/(.+)$/.exec(relativePath);
  if (!match) return null;
  const repositoryPath = match[3];
  const allowed = repositoryPath === "getpatched-preview-archive-keyring.asc" ||
    INDEX_FILES.has(repositoryPath) ||
    (repositoryPath.startsWith(PACKAGE_DIRECTORY) && PACKAGE_FILE.test(repositoryPath.slice(PACKAGE_DIRECTORY.length)));
  return allowed ? `runs/${match[1]}/${match[2]}/${repositoryPath}` : null;
}

function notFound() {
  return new Response("Not found\n", {
    status: 404,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });
}

function contentType(path) {
  if (path.endsWith(".deb")) return "application/vnd.debian.binary-package";
  if (path.endsWith(".gz")) return "application/gzip";
  if (path.endsWith(".xz")) return "application/x-xz";
  if (path.endsWith(".asc") || path.endsWith(".dsc") || path.endsWith("/Release") || path.endsWith("/InRelease") ||
      path.endsWith("/Packages") || path.endsWith("/Sources")) return "text/plain; charset=utf-8";
  return "application/pgp-signature";
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.hostname !== "preview.getpatched.dev") return notFound();
    if (request.method === "GET" && url.pathname === "/healthz") {
      return new Response(JSON.stringify({ ok: true, channel: "public-preview", readOnly: true }), {
        headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
      });
    }
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response("Method not allowed\n", {
        status: 405,
        headers: { allow: "GET, HEAD", "cache-control": "no-store" },
      });
    }

    if (/%|\\|\0|[\u0000-\u001f\u007f]/.test(url.pathname)) return notFound();
    const key = publicPath(url.pathname);
    if (!key || !env.PREVIEW) return notFound();

    let object;
    try {
      object = await env.PREVIEW.get(key);
    } catch {
      return new Response("Preview repository is unavailable\n", {
        status: 503,
        headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
      });
    }
    if (!object) return notFound();

    const metadataPath = key.includes("/dists/") || key.endsWith("archive-keyring.asc");
    const headers = new Headers({
      "content-type": contentType(key),
      "cache-control": metadataPath ? "no-cache, max-age=0, must-revalidate" : "public, max-age=31536000, immutable",
      "x-content-type-options": "nosniff",
    });
    if (Number.isSafeInteger(object.size)) headers.set("content-length", String(object.size));
    if (object.etag) headers.set("etag", `"${object.etag}"`);
    if (object.uploaded instanceof Date) headers.set("last-modified", object.uploaded.toUTCString());
    if (request.method === "HEAD") return new Response(null, { headers });
    return new Response(object.body, { headers });
  },
};
