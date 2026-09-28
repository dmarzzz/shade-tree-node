# Third-party notices

The `shadenet` release binaries statically link the Rust crates listed in `Cargo.lock`. Almost
all of them are under permissive licenses (MIT, Apache-2.0, BSD and similar; the allow list is
in `deny.toml`). Two are under the GNU Lesser General Public License, version 3:

| Crate | Version | License | Source |
|---|---|---|---|
| equix | 0.7.1 | LGPL-3.0-only | https://gitlab.torproject.org/tpo/core/arti (crates/equix) |
| hashx | 0.9.1 | LGPL-3.0-only | https://gitlab.torproject.org/tpo/core/arti (crates/hashx) |

They implement the Equi-X proof of work that Tor onion services use for denial-of-service
defense, and reach the binary through `arti-client`'s `hs-pow-full` feature.

**Your rights under the LGPL.** You may replace these libraries with modified versions. The
complete source of this program is public at https://github.com/dmarzzz/shade-tree-node under
the MIT license, and `Cargo.lock` pins the exact versions used, so you can rebuild the binary
against a modified equix or hashx (for example with a `[patch.crates-io]` entry) with
`cargo build --release -p shadenet-cli --features live`. The full text of the GNU LGPL v3 and
the GNU GPL v3 it incorporates is at https://www.gnu.org/licenses/lgpl-3.0.txt and
https://www.gnu.org/licenses/gpl-3.0.txt, and ships in each crate's source package.

Versions change with `Cargo.lock`; `cargo deny check licenses` fails CI if another copyleft
crate appears.
