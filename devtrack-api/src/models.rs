use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct Issue {
    pub id: i32,
    pub title: String,
    pub status: String,
    pub priority: String,
    pub user_id: i32,
    pub reporter_name: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateIssuePayload {
    pub title: String,
    pub priority: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateStatusPayload {
    pub status: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterPayload {
    pub name: String,
    pub email: String,
    pub password: String,
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginPayload {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct UserProfile {
    pub id: i32,
    pub name: String,
    pub email: String,
    pub role: String,
    pub total_bugs_reported: i32,
    pub open_bugs_count: i32,
}

#[derive(Debug, Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserProfile,
}
