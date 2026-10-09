//! Prints the JSON Schema bundle, for committing it:
//! `cargo run -p lotse-api-types --example schema > crates/lotse-api-types/schema/api.json`.

use std::io::Write as _;

fn main() -> std::io::Result<()> {
    std::io::stdout().write_all(lotse_api_types::schema::bundle_text().as_bytes())
}
