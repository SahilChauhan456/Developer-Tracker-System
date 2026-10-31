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

pub async fn login(
    State(pool): State<DbPool>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {

    eprintln!("[LOGIN] 1. Login request received");

    // 1. Acquire database connection
    let mut conn = pool.get().await.map_err(|e| {
        eprintln!("[LOGIN ERROR] Database connection: {}", e);
        internal_error(e)
    })?;

    eprintln!("[LOGIN] 2. Database connection acquired");

    // 2. Find user by email
    let stream = conn
        .query(
            "SELECT id, name, email, password_hash, role
             FROM users
             WHERE email = @P1",
            &[&payload.email],
        )
        .await
        .map_err(|e| {
            eprintln!("[LOGIN ERROR] User query: {}", e);
            internal_error(e)
        })?;

    eprintln!("[LOGIN] 3. User query executed");

    // 3. Read query result
    let row = stream
        .into_row()
        .await
        .map_err(|e| {
            eprintln!("[LOGIN ERROR] Reading user row: {}", e);
            internal_error(e)
        })?
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Invalid email or password".to_string(),
        ))?;

    eprintln!("[LOGIN] 4. User found");

    // 4. Extract user ID
    let user_id = row
        .try_get::<i32, _>("id")
        .map_err(internal_error)?
        .ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "User ID is missing".to_string(),
        ))?;

    // 5. Extract name
    let name = row
        .try_get::<&str, _>("name")
        .map_err(internal_error)?
        .unwrap_or_default()
        .to_string();

    // 6. Extract email
    let email = row
        .try_get::<&str, _>("email")
        .map_err(internal_error)?
        .unwrap_or_default()
        .to_string();

    // 7. Extract password hash
    let password_hash = row
        .try_get::<&str, _>("password_hash")
        .map_err(internal_error)?
        .unwrap_or_default()
        .to_string();

    // 8. Extract role
    let role = row
        .try_get::<&str, _>("role")
        .map_err(internal_error)?
        .unwrap_or("Full-Stack Developer")
        .to_string();

    drop(row);

    eprintln!("[LOGIN] 5. User information extracted");
    eprintln!(
        "[LOGIN] Password hash length: {}",
        password_hash.len()
    );

    if password_hash.is_empty() {
        eprintln!("[LOGIN ERROR] Stored password hash is empty");

        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Stored password hash is missing".to_string(),
        ));
    }

    // 9. Verify password
    eprintln!("[LOGIN] 6. Starting password verification");

    let is_valid = verify(&payload.password, &password_hash)
        .map_err(|e| {
            eprintln!("[LOGIN ERROR] Bcrypt verification: {}", e);
            internal_error(e)
        })?;

    if !is_valid {
        eprintln!("[LOGIN] Invalid password for {}", email);

        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid email or password".to_string(),
        ));
    }

    eprintln!("[LOGIN] 7. Password verified");

    // 10. Generate JWT
    let token = create_jwt(user_id, &email).map_err(|e| {
        eprintln!("[LOGIN ERROR] JWT generation: {}", e);
        internal_error(e)
    })?;

    eprintln!("[LOGIN] 8. JWT generated");

    // 11. Fetch profile using the existing connection
    let profile = match fetch_user_profile(&mut conn, user_id).await {
        Ok(Some(profile)) => profile,

        Ok(None) => {
            eprintln!("[LOGIN] Profile not found, using basic profile");

            UserProfile {
                id: user_id,
                name,
                email,
                role,
                total_bugs_reported: 0,
                open_bugs_count: 0,
            }
        }

        Err((_, error)) => {
            eprintln!(
                "[LOGIN WARNING] Profile statistics query failed: {}",
                error
            );

            UserProfile {
                id: user_id,
                name,
                email,
                role,
                total_bugs_reported: 0,
                open_bugs_count: 0,
            }
        }
    };

    eprintln!("[LOGIN] 9. Login successful");

    Ok(Json(AuthResponse {
        token,
        user: profile,
    }))
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
            u.id,
            u.name,
            u.email,
            u.role,
            CAST(COUNT(i.id) AS INT) AS total_bugs,
            CAST(
                ISNULL(
                    SUM(
                        CASE
                            WHEN i.status = 'Open' THEN 1
                            ELSE 0
                        END
                    ), 0
                ) AS INT
            ) AS open_bugs
        FROM users u
        LEFT JOIN issues i ON u.id = i.user_id
        WHERE u.id = @P1
        GROUP BY u.id, u.name, u.email, u.role
    ";

    let stream = conn
        .query(sql, &[&user_id])
        .await
        .map_err(internal_error)?;

    let row_opt = stream
        .into_row()
        .await
        .map_err(internal_error)?;

    let Some(row) = row_opt else {
        return Ok(None);
    };

    Ok(Some(UserProfile {
        id: row
            .try_get::<i32, _>("id")
            .map_err(internal_error)?
            .unwrap_or_default(),

        name: row
            .try_get::<&str, _>("name")
            .map_err(internal_error)?
            .unwrap_or_default()
            .to_string(),

        email: row
            .try_get::<&str, _>("email")
            .map_err(internal_error)?
            .unwrap_or_default()
            .to_string(),

        role: row
            .try_get::<&str, _>("role")
            .map_err(internal_error)?
            .unwrap_or_default()
            .to_string(),

        total_bugs_reported: row
            .try_get::<i32, _>("total_bugs")
            .map_err(internal_error)?
            .unwrap_or(0),

        open_bugs_count: row
            .try_get::<i32, _>("open_bugs")
            .map_err(internal_error)?
            .unwrap_or(0),
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
