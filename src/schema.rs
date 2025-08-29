use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Comment {
    id: i32,
    username: String,
    contents: String,
}
