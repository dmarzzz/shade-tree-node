# Live Protocol Lab runner

`runner.mjs` is a deliberately fixed-purpose server for the hosted Lab. It is
not a general proxy:

- the only destination is `https://example.com/`;
- `POST /v1/run` accepts only an empty JSON object and a server-side bearer token;
- one run may be active at once, with a 16-second start cooldown;
- node onions become per-run aliases before streaming;
- the public Groth16 signals and proof points remain exact;
- the invited member secret never leaves the runner environment.

Run it behind a TLS reverse proxy with a local Tor SOCKS listener:

```text
SHADE_TREE_LAB_RUNNER_TOKEN=<random-32+-character-token>
SHADE_TREE_SECRET=<limited-invited-member-secret>
SHADE_TREE_BOOTNODE_ONION=<live-v4-elder.onion>
SHADE_TREE_DIR_SIGNER=<live-v4-canopy-signer>
SHADE_TREE_MEMBERS_FILE=/private/members.json
SHADE_TREE_TOR_PORT=9260
SHADE_TREE_SLOT_STATE_DIR=/private/durable-state
node lab/runner.mjs
```

The website's Lab page and the Vercel function that called `POST /v1/run`
(`docs/post/api/lab-run.mjs`) were removed in October 2026, so nothing in this
repository calls that route now. The Lab host stays in the fleet for the
operator end-to-end check after each roll and the five-minute uptime probe
(`monitoring/UPTIME.md`).
