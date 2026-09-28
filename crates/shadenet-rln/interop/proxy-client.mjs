// Minimal HTTP CONNECT client for proxy-run.sh. It sends application bytes in
// the same write as the headers, exercising the Rust Proxy's early-data path as
// well as the accepted tunnel relay.
import net from "node:net";

const [proxyPortArg, target, payload = "interop-ping", token] = process.argv.slice(2);
const proxyPort = Number(proxyPortArg);

if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535 || !target || !token) {
  console.error("usage: node proxy-client.mjs <proxy-port> <target-host:port> [payload] <token>");
  process.exit(2);
}

const expected = `shade-tree-proxy-ok:${payload}`;
const chunks = [];
const socket = net.connect(proxyPort, "127.0.0.1", () => {
  const credential = Buffer.from(`shade-tree:${token}`, "utf8").toString("base64");
  socket.write(
    `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\nProxy-Authorization: Basic ${credential}\r\nConnection: close\r\n\r\n${payload}`,
  );
});

socket.setTimeout(180_000, () => socket.destroy(new Error("proxy response timed out")));
socket.on("data", (chunk) => chunks.push(chunk));
socket.on("error", (error) => {
  console.error(`proxy client: ${error.message}`);
  process.exitCode = 1;
});
socket.on("close", () => {
  if (process.exitCode) return;
  const response = Buffer.concat(chunks).toString("utf8");
  if (!response.startsWith("HTTP/1.1 200 Connection Established\r\n")) {
    console.error(`proxy client: missing CONNECT acceptance: ${response.slice(0, 200)}`);
    process.exitCode = 1;
    return;
  }
  if (!response.includes(expected)) {
    console.error(`proxy client: missing relayed payload ${JSON.stringify(expected)}`);
    process.exitCode = 1;
    return;
  }
  console.log("PASS: Rust CONNECT Proxy relayed early application bytes after gateway acceptance");
});
