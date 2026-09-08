# Shade Tree Grove specifications

These files are the canonical, implementation-grounded contracts for Shade Tree
Grove. Presentation names do not rename wire roles or identifiers.

| Specification | Scope |
| --- | --- |
| [`protocol.md`](protocol.md) | Protocol roles, tunnel flow, admission, discovery, trust boundaries, and versioning |
| [`WIRE-SPEC.md`](../docs/WIRE-SPEC.md) | Byte-level wire formats and the Elder Tree HTTP API |
| [`VERSIONING.md`](../docs/VERSIONING.md) | Envelope negotiation, artifact rotation, and coordinated rollout |
| [`data-api.md`](data-api.md) | Signed public Grove aggregate, publisher/observer separation, privacy contract, caching, and evolution rules |
| [`data-api.openapi.yaml`](data-api.openapi.yaml) | OpenAPI 3.1 description of the currently implemented public read endpoint only |

The former `docs/PROTOCOL-API.md` and `docs/PROTOCOL-VERSIONING.md` paths remain
compatibility indexes; new references should use the canonical documents above.
