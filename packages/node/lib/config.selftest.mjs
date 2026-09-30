// Selftest for packages/node/lib/config.mjs — the SHADE_TREE_* env validator each entrypoint will fail-fast on.
// Covers: every field validator's accept/reject edge, and per role (bootnode, gateway, client,
// member-enroll) that a VALID env passes clean, a MISSING required var and a MALFORMED value each
// fail on the RIGHT var, optional-absent is fine, and the client's three discovery modes
// (pinned onion / static directory / live bootnode) each validate.
//
//   node packages/node/lib/config.selftest.mjs
//
// Exit 0 = all invariants held. No network, no chain, no filesystem.

import { generateKeyPairSync } from "node:crypto";
import { Wallet } from "ethers";
import { pubkeyToOnion } from "./directory.mjs";
import {
  isOnion, isEd25519PubHex, isPrivHex, isEthAddress, isPort, isPortOrOff,
  isUrl, isField, isPosInt, isNonNegInt, isEnum,
  validateConfig, ROLES, ROLE_SPECS,
} from "./config.mjs";

let failures = 0;
const ok = (cond, msg) => { if (cond) console.log(`  ok   ${msg}`); else { console.log(`  FAIL ${msg}`); failures++; } };

// Real values: a genuine v3 onion + its ed25519 pubkey (via pubkeyToOnion), and a real address.
function newEd() {
  const { publicKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" });
  return der.subarray(der.length - 32).toString("hex");
}
const SIGNER = newEd();                       // 64-hex ed25519 pubkey (directory signer)
const PUB = newEd();
const ONION = pubkeyToOnion(PUB);             // a real, checksum-valid v3 .onion for PUB
const BOOT_ONION = pubkeyToOnion(newEd());
const ADDR = Wallet.createRandom().address;   // a real (EIP-55) ethers address
const PRIV = Wallet.createRandom().privateKey; // 0x + 64 hex
const SECRET = "0x" + Buffer.from(newEd(), "hex").toString("hex"); // 32-byte 0x-hex field secret

// find one error for a var (or undefined)
const errFor = (res, name) => res.errors.find((e) => e.var === name);

function main() {
  console.log("field validators:");
  {
    // isOnion
    ok(isOnion(ONION), "isOnion accepts a real v3 onion");
    ok(isOnion(ONION.replace(/\.onion$/, "")), "isOnion accepts the bare 56-char form");
    ok(!isOnion("tooshort.onion"), "isOnion rejects a short address");
    ok(!isOnion(ONION.replace(/^./, (c) => (c === "a" ? "b" : "a"))), "isOnion rejects a checksum-broken onion");
    ok(!isOnion(undefined) && !isOnion(123), "isOnion is total on non-strings");

    // isEd25519PubHex
    ok(isEd25519PubHex(SIGNER), "isEd25519PubHex accepts 64 hex");
    ok(!isEd25519PubHex("0x" + SIGNER), "isEd25519PubHex rejects a 0x prefix");
    ok(!isEd25519PubHex(SIGNER.slice(0, 63)), "isEd25519PubHex rejects 63 chars");
    ok(!isEd25519PubHex("z".repeat(64)), "isEd25519PubHex rejects non-hex");

    // isPrivHex
    ok(isPrivHex(PRIV) && isPrivHex(PRIV.slice(2)), "isPrivHex accepts 0x and bare 64-hex");
    ok(!isPrivHex("0x" + "f".repeat(63)), "isPrivHex rejects wrong length");

    // isEthAddress
    ok(isEthAddress(ADDR), "isEthAddress accepts a real address");
    ok(!isEthAddress(ADDR.slice(0, 41)), "isEthAddress rejects a truncated address");
    ok(!isEthAddress(SIGNER), "isEthAddress rejects a 64-hex non-address");

    // isPort / isPortOrOff
    ok(isPort("1") && isPort("65535"), "isPort accepts the range ends");
    ok(!isPort("0") && !isPort("65536") && !isPort("8x"), "isPort rejects 0, >max, non-numeric");
    ok(isPortOrOff("0") && isPortOrOff("9090") && !isPortOrOff("70000"), "isPortOrOff allows 0, rejects >max");

    // isUrl
    ok(isUrl("http://127.0.0.1:8545") && isUrl("https://rpc.example.com"), "isUrl accepts http(s)");
    ok(!isUrl("127.0.0.1:8545") && !isUrl("ftp://x") && !isUrl("not a url"), "isUrl rejects bare host / wrong scheme / junk");

    // isField
    ok(isField(SECRET) && isField("12345"), "isField accepts 0x-hex and decimal positives");
    ok(!isField("0") && !isField("0x0"), "isField rejects zero");
    ok(!isField("-5") && !isField("deadbeef") && !isField(""), "isField rejects negative / non-numeric / empty");

    // isPosInt / isNonNegInt / isEnum
    ok(isPosInt("1") && !isPosInt("0") && !isPosInt("-1"), "isPosInt is strictly positive");
    ok(isNonNegInt("0") && isNonNegInt("7") && !isNonNegInt("-1"), "isNonNegInt allows 0");
    ok(isEnum("open", ["open", "stake"]) && !isEnum("nope", ["open", "stake"]), "isEnum membership");
  }

  console.log("\nroles registry:");
  ok(ROLES.length === 4 && ROLES.every((r) => ROLE_SPECS[r]), "four roles registered with specs");
  ok(!validateConfig("bogus-role").ok && errFor(validateConfig("bogus-role"), "role"), "unknown role is a hard error");

  console.log("\nbootnode role:");
  {
    // minimal valid: empty env is fine (all defaulted, mock stake)
    ok(validateConfig("bootnode", {}).ok, "empty env is valid (everything defaulted, chainless)");

    // valid onchain stake config
    const good = { SHADE_TREE_BOOTNODE_ADMISSION: "stake", SHADE_TREE_STAKE_MODE: "onchain", SHADE_TREE_GATEWAY_REGISTRY: ADDR, SHADE_TREE_RPC_URL: "http://127.0.0.1:8545", SHADE_TREE_BOOTNODE_PORT: "8877" };
    ok(validateConfig("bootnode", good).ok, "onchain stake with registry + rpc passes");

    // MISSING required (conditional): onchain mode without the registry
    const missReg = { SHADE_TREE_STAKE_MODE: "onchain" };
    ok(errFor(validateConfig("bootnode", missReg), "SHADE_TREE_GATEWAY_REGISTRY"), "onchain without SHADE_TREE_GATEWAY_REGISTRY fails on that var");

    // MALFORMED values fall on the right var
    ok(errFor(validateConfig("bootnode", { SHADE_TREE_GATEWAY_REGISTRY: "0xnothex" }), "SHADE_TREE_GATEWAY_REGISTRY"), "bad registry address fails on SHADE_TREE_GATEWAY_REGISTRY");
    ok(errFor(validateConfig("bootnode", { SHADE_TREE_BOOTNODE_PORT: "70000" }), "SHADE_TREE_BOOTNODE_PORT"), "out-of-range port fails on SHADE_TREE_BOOTNODE_PORT");
    ok(errFor(validateConfig("bootnode", { SHADE_TREE_BOOTNODE_ADMISSION: "maybe" }), "SHADE_TREE_BOOTNODE_ADMISSION"), "bad admission enum fails on SHADE_TREE_BOOTNODE_ADMISSION");
    ok(errFor(validateConfig("bootnode", { SHADE_TREE_RPC_URL: "127.0.0.1" }), "SHADE_TREE_RPC_URL"), "bad rpc url fails on SHADE_TREE_RPC_URL");
    ok(validateConfig("bootnode", { SHADE_TREE_LOG_LEVEL: "debug", SHADE_TREE_LOG_FORMAT: "pretty", SHADE_TREE_BANNER: "always", SHADE_TREE_METRICS_PORT: "9100" }).ok, "operator logging and metrics options pass");
    ok(errFor(validateConfig("bootnode", { SHADE_TREE_LOG_LEVEL: "verbose" }), "SHADE_TREE_LOG_LEVEL"), "unknown log level fails on SHADE_TREE_LOG_LEVEL");
    ok(errFor(validateConfig("bootnode", { SHADE_TREE_LOG_FORMAT: "xml" }), "SHADE_TREE_LOG_FORMAT"), "unknown log format fails on SHADE_TREE_LOG_FORMAT");
    ok(errFor(validateConfig("bootnode", { SHADE_TREE_METRICS_PORT: "70000" }), "SHADE_TREE_METRICS_PORT"), "invalid operator metrics port fails on SHADE_TREE_METRICS_PORT");
    ok(errFor(validateConfig("bootnode", { SHADE_TREE_BOOTNODE_PORT: "8877", SHADE_TREE_METRICS_PORT: "8877" }), "SHADE_TREE_METRICS_PORT"), "Elder metrics cannot reuse its Tor-mapped backend port");

    // optional absent is fine (registry set => onchain, present => ok)
    ok(validateConfig("bootnode", { SHADE_TREE_GATEWAY_REGISTRY: ADDR }).ok, "registry alone (=> onchain) is valid; other optionals absent is fine");
  }

  console.log("\ngateway role:");
  {
    ok(validateConfig("gateway", {}).ok, "empty env is valid (members.json fallback, dry-run, mock)");

    const good = { SHADE_TREE_GATEWAY_PORT: "8443", SHADE_TREE_GROUP_CONTRACT: ADDR, SHADE_TREE_ROOT_PROVIDER: "node", SHADE_TREE_SLASH_KEY: PRIV, SHADE_TREE_SLASH_CONTRACT: ADDR, SHADE_TREE_RPC_URL: "http://127.0.0.1:8545", SHADE_TREE_METRICS_PORT: "0" };
    ok(validateConfig("gateway", good).ok, "full on-chain gateway config passes");

    ok(errFor(validateConfig("gateway", { SHADE_TREE_GROUP_CONTRACT: "notanaddr" }), "SHADE_TREE_GROUP_CONTRACT"), "bad group contract fails on SHADE_TREE_GROUP_CONTRACT");
    ok(errFor(validateConfig("gateway", { SHADE_TREE_SLASH_KEY: "0x1234" }), "SHADE_TREE_SLASH_KEY"), "malformed slash key fails on SHADE_TREE_SLASH_KEY");
    ok(errFor(validateConfig("gateway", { SHADE_TREE_ROOT_PROVIDER: "helios" }), "SHADE_TREE_ROOT_PROVIDER"), "bad root-provider enum fails on SHADE_TREE_ROOT_PROVIDER");
    ok(errFor(validateConfig("gateway", { SHADE_TREE_EPOCH_SECONDS: "0" }), "SHADE_TREE_EPOCH_SECONDS"), "non-positive epoch fails on SHADE_TREE_EPOCH_SECONDS");
    ok(errFor(validateConfig("gateway", { SHADE_TREE_GATEWAY_PORT: "70000" }), "SHADE_TREE_GATEWAY_PORT"), "out-of-range gateway port fails on SHADE_TREE_GATEWAY_PORT");
    ok(validateConfig("gateway", { SHADE_TREE_HEARTBEAT_METRICS_PORT: "9103" }).ok, "heartbeat metrics port is valid in the gateway-side role");
    ok(errFor(validateConfig("gateway", { SHADE_TREE_HEARTBEAT_METRICS_PORT: "nope" }), "SHADE_TREE_HEARTBEAT_METRICS_PORT"), "bad heartbeat metrics port is rejected");
    ok(errFor(validateConfig("gateway", { SHADE_TREE_GATEWAY_PORT: "8443", SHADE_TREE_METRICS_PORT: "8443" }), "SHADE_TREE_METRICS_PORT"), "node metrics cannot reuse its Tor-mapped backend port");
  }

  console.log("\nclient role — three discovery modes:");
  {
    // (a) pinned onion
    const pin = { SHADE_TREE_SECRET: SECRET, SHADE_TREE_ONION: ONION };
    ok(validateConfig("client", pin).ok, "mode (a): secret + pinned onion passes");

    // (b) static signed directory
    const staticDir = { SHADE_TREE_SECRET: SECRET, SHADE_TREE_DIRECTORY: "group/directory.example.json", SHADE_TREE_DIR_SIGNER: SIGNER };
    ok(validateConfig("client", staticDir).ok, "mode (b): secret + directory + dir-signer passes");

    // (c) live bootnode
    const boot = { SHADE_TREE_SECRET: SECRET, SHADE_TREE_BOOTNODE_ONION: BOOT_ONION, SHADE_TREE_DIR_SIGNER: SIGNER };
    ok(validateConfig("client", boot).ok, "mode (c): secret + bootnode onion + dir-signer passes");

    // MISSING required secret
    ok(errFor(validateConfig("client", { SHADE_TREE_ONION: ONION }), "SHADE_TREE_SECRET"), "missing SHADE_TREE_SECRET fails on SHADE_TREE_SECRET");

    // MALFORMED: bad onion, non-hex signer, non-field secret each on the right var
    ok(errFor(validateConfig("client", { SHADE_TREE_SECRET: SECRET, SHADE_TREE_ONION: "deadbeef.onion" }), "SHADE_TREE_ONION"), "malformed onion fails on SHADE_TREE_ONION");
    ok(errFor(validateConfig("client", { ...pin, SHADE_TREE_SHIM_PORT: "8888", SHADE_TREE_METRICS_PORT: "8888" }), "SHADE_TREE_METRICS_PORT"), "Proxy metrics cannot reuse its local CONNECT port");
    ok(errFor(validateConfig("client", { SHADE_TREE_SECRET: SECRET, SHADE_TREE_DIRECTORY: "d.json", SHADE_TREE_DIR_SIGNER: "0x" + SIGNER }), "SHADE_TREE_DIR_SIGNER"), "0x-prefixed signer fails on SHADE_TREE_DIR_SIGNER");
    ok(errFor(validateConfig("client", { SHADE_TREE_SECRET: "0x0", SHADE_TREE_ONION: ONION }), "SHADE_TREE_SECRET"), "zero secret fails on SHADE_TREE_SECRET (non-field)");

    // no discovery configured at all
    ok(errFor(validateConfig("client", { SHADE_TREE_SECRET: SECRET }), "SHADE_TREE_ONION"), "secret but no discovery mode fails (attributed to SHADE_TREE_ONION with a mode hint)");

    // directory/bootnode set WITHOUT the pinned signer => misconfig on SHADE_TREE_DIR_SIGNER
    ok(errFor(validateConfig("client", { SHADE_TREE_SECRET: SECRET, SHADE_TREE_DIRECTORY: "d.json" }), "SHADE_TREE_DIR_SIGNER"), "directory without dir-signer fails on SHADE_TREE_DIR_SIGNER");

    // optional absent (no shim-port etc.) is fine
    ok(validateConfig("client", pin).errors.length === 0, "valid client has zero errors (optionals absent ok)");
  }

  console.log("\nmember-enroll role:");
  {
    ok(validateConfig("member-enroll", {}).ok, "empty env is valid (enroll reads no env; register falls back)");
    const good = { SHADE_TREE_GROUP_CONTRACT: ADDR, SHADE_TREE_RPC_URL: "http://127.0.0.1:8545", SHADE_TREE_REGISTER_KEY: PRIV, SHADE_TREE_BOND: "1000000000000000000" };
    ok(validateConfig("member-enroll", good).ok, "full on-chain register config passes");
    ok(errFor(validateConfig("member-enroll", { SHADE_TREE_GROUP_CONTRACT: "0xzz" }), "SHADE_TREE_GROUP_CONTRACT"), "bad contract address fails on SHADE_TREE_GROUP_CONTRACT");
    ok(errFor(validateConfig("member-enroll", { SHADE_TREE_BOND: "-1" }), "SHADE_TREE_BOND"), "negative bond fails on SHADE_TREE_BOND");
    ok(errFor(validateConfig("member-enroll", { SHADE_TREE_REGISTER_KEY: "nothex" }), "SHADE_TREE_REGISTER_KEY"), "malformed register key fails on SHADE_TREE_REGISTER_KEY");
  }

  console.log(`\n${failures === 0 ? "PASS" : "FAIL"}: config selftest (${failures} failure${failures === 1 ? "" : "s"})`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
