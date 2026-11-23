//! Prints the JSON Schema bundle, for committing it:
//! `cargo run -p rocko-api-types --features schema --example schema > crates/rocko-api-types/schema/api.json`.

use std::io::Write as _;

fn main() -> std::io::Result<()> {
    std::io::stdout().write_all(rocko_api_types::schema::bundle_text().as_bytes())
}
