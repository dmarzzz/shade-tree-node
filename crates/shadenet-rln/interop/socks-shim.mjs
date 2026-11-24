// A SOCKS5 stand-in for Tor on loopback: every onion a client dials is routed to a local port
// from the map given on the command line, so a harness can put the Rust node, the Rust Elder
// and the JavaScript Elder behind "onions" without a Tor daemon. Unmapped names are refused
// (host unreachable), which is what a dead onion looks like to a client.
//
// Usage: node socks-shim.mjs <listen-port> '{"<addr>.onion":<port>,...}'
import net from "node:net";

const port = Number(process.argv[2]);
const routes = JSON.parse(process.argv[3] || "{}");
if (!Number.isInteger(port) || port < 1) {
  console.error("usage: node socks-shim.mjs <listen-port> '{\"<onion>\":<port>}'");
  process.exit(2);
}

function readExact(socket, n, pending) {
  return new Promise((resolve, reject) => {
    const take = () => {
      if (pending.buffer.length >= n) {
        const out = pending.buffer.subarray(0, n);
        pending.buffer = pending.buffer.subarray(n);
        socket.removeListener("data", onData);
        socket.removeListener("error", reject);
        resolve(out);
      }
    };
    const onData = (chunk) => { pending.buffer = Buffer.concat([pending.buffer, chunk]); take(); };
    socket.on("data", onData);
    socket.once("error", reject);
    take();
  });
}

const server = net.createServer(async (socket) => {
  const pending = { buffer: Buffer.alloc(0) };
  socket.on("error", () => {});
  try {
    const greeting = await readExact(socket, 2, pending);
    await readExact(socket, greeting[1], pending);
    socket.write(Buffer.from([5, 0]));
    const head = await readExact(socket, 4, pending);
    if (head[1] !== 1 || head[3] !== 3) { socket.end(Buffer.from([5, 7, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
    const length = (await readExact(socket, 1, pending))[0];
    const name = (await readExact(socket, length, pending)).toString("utf8");
    await readExact(socket, 2, pending);
    const target = routes[name.toLowerCase()];
    if (!target) { socket.end(Buffer.from([5, 4, 0, 1, 0, 0, 0, 0, 0, 0])); return; }
    const upstream = net.connect(target, "127.0.0.1");
    upstream.on("error", () => socket.destroy());
    upstream.once("connect", () => {
      socket.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
      if (pending.buffer.length) upstream.write(pending.buffer);
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
  } catch {
    socket.destroy();
  }
});
server.listen(port, "127.0.0.1", () => console.error(`[shim] up on 127.0.0.1:${port}`));
