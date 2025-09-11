use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub avatar_url: String,
}

#[derive(Deserialize, Serialize)]
pub struct Post {
    pub id: i32,
    pub name: String,
}

#[derive(Deserialize, Serialize)]
pub struct Comment {
    pub id: i32,
    pub post_id: i32,
    pub user_id: i32,
    pub contents: String,
}
