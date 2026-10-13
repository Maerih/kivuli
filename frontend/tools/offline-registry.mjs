// Build-time only: serves the tarballs fetched by tools/fetch_deps.py at the same
// paths the npm registry uses, so `npm ci --registry http://127.0.0.1:4873/`
// installs without touching the network. npm still checks every tarball against
// the integrity hash in package-lock.json.
import { createReadStream, statSync } from "node:fs";
import { createServer } from "node:http";
import { join, resolve } from "node:path";

const root = resolve(process.argv[2]);

createServer((req, res) => {
  const file = join(root, decodeURIComponent(new URL(req.url, "http://localhost").pathname));
  let size = -1;
  try {
    if (file.startsWith(root)) size = statSync(file).isFile() ? statSync(file).size : -1;
  } catch {
    size = -1;
  }
  if (size < 0) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { "content-type": "application/octet-stream", "content-length": size });
  createReadStream(file).pipe(res);
}).listen(4873, "127.0.0.1");
