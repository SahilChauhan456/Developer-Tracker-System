use crate::{
    auth::{AuthUser, create_jwt},
    db::DbPool,
    models::{
        AuthResponse, CreateIssuePayload, Issue, LoginPayload, RegisterPayload,
        UpdateStatusPayload, UserProfile,
    },
};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use bcrypt::{DEFAULT_COST, hash, verify};

fn internal_error<E: std::fmt::Display>(err: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

// POST /api/auth/register
pub async fn register(
    State(pool): State<DbPool>,
    Json(payload): Json<RegisterPayload>,
) -> Result<(StatusCode, Json<AuthResponse>), (StatusCode, String)> {
    let mut conn = pool.get().await.map_err(internal_error)?;

    let password_hash = hash(&payload.password, DEFAULT_COST).map_err(internal_error)?;
    let role = payload
        .role
        .unwrap_or_else(|| "Full-Stack Developer".to_string());

    let stream = conn
        .query(
            "INSERT INTO users (name, email, password_hash, role) OUTPUT INSERTED.id VALUES (@P1, @P2, @P3, @P4)",
            &[&payload.name, &payload.email, &password_hash, &role],
        )
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Registration failed (email may already exist): {}", e)))?;

    let row = stream.into_row().await.map_err(internal_error)?.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to get user ID".to_string(),
    ))?;

    let user_id: i32 = row.get("id").unwrap_or_default();
    let token = create_jwt(user_id, &payload.email).map_err(internal_error)?;

    let user = UserProfile {
        id: user_id,
        name: payload.name,
        email: payload.email,
        role,
        total_bugs_reported: 0,
        open_bugs_count: 0,
    };

    Ok((StatusCode::CREATED, Json(AuthResponse { token, user })))
}

// POST /api/auth/login
// POST /api/auth/login
pub async fn login(
    State(pool): State<DbPool>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    let mut conn = pool.get().await.map_err(internal_error)?;

    let stream = conn
        .query(
            "SELECT id, name, email, password_hash, role FROM users WHERE email = @P1",
            &[&payload.email],
        )
        .await
        .map_err(internal_error)?;

    let row = stream.into_row().await.map_err(internal_error)?.ok_or((
        StatusCode::UNAUTHORIZED,
        "Invalid email or password".to_string(),
    ))?;

    let user_id: i32 = row.try_get("id").ok().flatten().unwrap_or_default();
    let name = row
        .try_get::<&str, _>("name")
        .ok()
        .flatten()
        .unwrap_or_default()
        .to_string();
    let email = row
        .try_get::<&str, _>("email")
        .ok()
        .flatten()
        .unwrap_or_default()
        .to_string();
    let hash_str = row
        .try_get::<&str, _>("password_hash")
        .ok()
        .flatten()
        .unwrap_or_default()
        .to_string();
    let role = row
        .try_get::<&str, _>("role")
        .ok()
        .flatten()
        .unwrap_or_default()
        .to_string();

    let is_valid = verify(&payload.password, &hash_str).map_err(internal_error)?;
    if !is_valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid email or password".to_string(),
        ));
    }

    let token = create_jwt(user_id, &email).map_err(internal_error)?;

    // Drop the connection borrow cleanly before getting a new one or returning
    drop(conn);

    let profile = fetch_user_profile_by_id(&pool, user_id)
        .await
        .unwrap_or(UserProfile {
            id: user_id,
            name: name.clone(),
            email: email.clone(),
            role: role.clone(),
            total_bugs_reported: 0,
            open_bugs_count: 0,
        });

    Ok(Json(AuthResponse {
        token,
        user: profile,
    }))
}

// Separate helper that acquires its own connection from the pool safely
async fn fetch_user_profile_by_id(
    pool: &DbPool,
    user_id: i32,
) -> Result<UserProfile, (StatusCode, String)> {
    let mut conn = pool.get().await.map_err(internal_error)?;
    let sql = "
        SELECT 
            u.id, u.name, u.email, u.role,
            COUNT(i.id) AS total_bugs,
            ISNULL(SUM(CASE WHEN i.status = 'Open' THEN 1 ELSE 0 END), 0) AS open_bugs
        FROM users u
        LEFT JOIN issues i ON u.id = i.user_id
        WHERE u.id = @P1
        GROUP BY u.id, u.name, u.email, u.role
    ";

    let stream = conn.query(sql, &[&user_id]).await.map_err(internal_error)?;
    let row_opt = stream.into_row().await.map_err(internal_error)?;

    let row = row_opt.ok_or((StatusCode::NOT_FOUND, "User profile not found".to_string()))?;

    Ok(UserProfile {
        id: row
            .try_get::<i32, _>("id")
            .ok()
            .flatten()
            .unwrap_or_default(),
        name: row
            .try_get::<&str, _>("name")
            .ok()
            .flatten()
            .unwrap_or_default()
            .to_string(),
        email: row
            .try_get::<&str, _>("email")
            .ok()
            .flatten()
            .unwrap_or_default()
            .to_string(),
        role: row
            .try_get::<&str, _>("role")
            .ok()
            .flatten()
            .unwrap_or_default()
            .to_string(),
        total_bugs_reported: row
            .try_get::<i32, _>("total_bugs")
            .ok()
            .flatten()
            .unwrap_or(0),
        open_bugs_count: row
            .try_get::<i32, _>("open_bugs")
            .ok()
            .flatten()
            .unwrap_or(0),
    })
}

// GET /api/profile (Protected)
pub async fn get_profile(
    auth: AuthUser,
    State(pool): State<DbPool>,
) -> Result<Json<UserProfile>, (StatusCode, String)> {
    let mut conn = pool.get().await.map_err(internal_error)?;

    let profile = fetch_user_profile(&mut conn, auth.user_id)
        .await?
        .ok_or((StatusCode::NOT_FOUND, "User not found".to_string()))?;

    Ok(Json(profile))
}

async fn fetch_user_profile(
    conn: &mut bb8::PooledConnection<'_, bb8_tiberius::ConnectionManager>,
    user_id: i32,
) -> Result<Option<UserProfile>, (StatusCode, String)> {
    let sql = "
        SELECT 
            u.id, u.name, u.email, u.role,
            COUNT(i.id) AS total_bugs,
            SUM(CASE WHEN i.status = 'Open' THEN 1 ELSE 0 END) AS open_bugs
        FROM users u
        LEFT JOIN issues i ON u.id = i.user_id
        WHERE u.id = @P1
        GROUP BY u.id, u.name, u.email, u.role
    ";

    let stream = conn.query(sql, &[&user_id]).await.map_err(internal_error)?;
    let row_opt = stream.into_row().await.map_err(internal_error)?;

    Ok(row_opt.map(|row| UserProfile {
        id: row.get::<i32, _>("id").unwrap_or_default(),
        name: row.get::<&str, _>("name").unwrap_or_default().to_string(),
        email: row.get::<&str, _>("email").unwrap_or_default().to_string(),
        role: row.get::<&str, _>("role").unwrap_or_default().to_string(),
        total_bugs_reported: row.get::<i32, _>("total_bugs").unwrap_or(0),
        open_bugs_count: row.get::<i32, _>("open_bugs").unwrap_or(0),
    }))
}

// GET /api/issues (Public)
pub async fn get_issues(
    State(pool): State<DbPool>,
) -> Result<Json<Vec<Issue>>, (StatusCode, String)> {
    let mut conn = pool.get().await.map_err(internal_error)?;

    let sql = "
        SELECT 
            i.id, i.title, i.status, i.priority,
            ISNULL(i.user_id, 0) AS user_id,
            ISNULL(u.name, 'System') AS reporter_name
        FROM issues i
        LEFT JOIN users u ON i.user_id = u.id
        ORDER BY i.id DESC
    ";

    let stream = conn.query(sql, &[]).await.map_err(internal_error)?;
    let rows = stream.into_first_result().await.map_err(internal_error)?;

    let issues = rows
        .into_iter()
        .map(|row| Issue {
            id: row.get::<i32, _>("id").unwrap_or_default(),
            title: row.get::<&str, _>("title").unwrap_or_default().to_string(),
            status: row.get::<&str, _>("status").unwrap_or_default().to_string(),
            priority: row
                .get::<&str, _>("priority")
                .unwrap_or_default()
                .to_string(),
            user_id: row.get::<i32, _>("user_id").unwrap_or_default(),
            reporter_name: row
                .get::<&str, _>("reporter_name")
                .unwrap_or_default()
                .to_string(),
        })
        .collect();

    Ok(Json(issues))
}

// POST /api/issues (Protected - requires logged-in user)
pub async fn create_issue(
    auth: AuthUser,
    State(pool): State<DbPool>,
    Json(payload): Json<CreateIssuePayload>,
) -> Result<(StatusCode, Json<Issue>), (StatusCode, String)> {
    let mut conn = pool.get().await.map_err(internal_error)?;
    let default_status = "Open";

    let stream = conn
        .query(
            "INSERT INTO issues (title, status, priority, user_id) OUTPUT INSERTED.id VALUES (@P1, @P2, @P3, @P4)",
            &[&payload.title, &default_status, &payload.priority, &auth.user_id],
        )
        .await
        .map_err(internal_error)?;

    let row = stream.into_row().await.map_err(internal_error)?.ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        "Failed to retrieve inserted ID".to_string(),
    ))?;

    let new_id: i32 = row.get("id").unwrap_or_default();

    let created = Issue {
        id: new_id,
        title: payload.title,
        status: default_status.to_string(),
        priority: payload.priority,
        user_id: auth.user_id,
        reporter_name: "You".to_string(),
    };

    Ok((StatusCode::CREATED, Json(created)))
}

// PATCH /api/issues/{id} (Protected)
pub async fn update_issue_status(
    _auth: AuthUser,
    State(pool): State<DbPool>,
    Path(id): Path<i32>,
    Json(payload): Json<UpdateStatusPayload>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = pool.get().await.map_err(internal_error)?;

    conn.execute(
        "UPDATE issues SET status = @P1 WHERE id = @P2",
        &[&payload.status, &id],
    )
    .await
    .map_err(internal_error)?;

    Ok(StatusCode::NO_CONTENT)
}

// DELETE /api/issues/{id} (Protected)
pub async fn delete_issue(
    _auth: AuthUser,
    State(pool): State<DbPool>,
    Path(id): Path<i32>,
) -> Result<StatusCode, (StatusCode, String)> {
    let mut conn = pool.get().await.map_err(internal_error)?;

    conn.execute("DELETE FROM issues WHERE id = @P1", &[&id])
        .await
        .map_err(internal_error)?;

    Ok(StatusCode::NO_CONTENT)
}
