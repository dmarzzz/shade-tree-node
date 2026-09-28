# shade_tree_v4 is maintained here (OPS-18)

This role is the single copy. Operator infrastructure consumes it from the pinned source
checkout of the release it deploys (`<checkout>/deploy/v4/ansible/roles`) instead of vendoring
it, so the role and the code it installs always come from the same commit. Change it here, in
the same pull request as any code it deploys.

The `public-stake-v1` assertions pin that profile's published economics. A deployment with new
economics uses a new profile id in its record.
