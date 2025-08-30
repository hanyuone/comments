use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct Post {
    pub id: i32,
}

#[derive(Deserialize, Serialize)]
pub struct Comment {
    pub id: i32,
    pub username: String,
    pub contents: String,
}

#[derive(Deserialize)]
pub struct NewComment {
    pub username: String,
    pub contents: String,
}
