//! Print the depth-20 Poseidon root of a members file (`{"members": ["<leaf>", ...]}`).
//!
//!   cargo run -p shadenode --example members_root -- members.json [rln-identifier]
fn main() {
    let path = std::env::args().nth(1).expect("members file");
    let id: u64 = std::env::args()
        .nth(2)
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let members: Vec<String> = json["members"]
        .as_array()
        .expect("`members` array")
        .iter()
        .map(|m| m.as_str().expect("string leaf").to_string())
        .collect();
    println!("{}", shadenode::rln::members_root(id, &members).unwrap());
}
