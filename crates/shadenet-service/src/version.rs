//! The source commit stamped at build time (`build.rs`): `SHADENET_BUILD_COMMIT` from a
//! packager, else `GITHUB_SHA`, else `git rev-parse HEAD`, else `unknown`.

/// The first twelve hex characters of the commit this workspace was built from.
pub const COMMIT: &str = env!("SHADENET_COMMIT");
