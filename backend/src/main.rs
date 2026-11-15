// SlopShop — v0 baseline backend (Axum + SQLite)
// =================================================================
// INTENTIONALLY INSECURE training application for DFCS H4013 (CA3).
// Localhost + synthetic data only. Every `VULN-xx` tag marks a
// deliberate weakness that is documented in docs/VULNERABILITIES.md
// and tested in the security verification matrix. DO NOT DEPLOY.
// =================================================================

use std::{
    fs,
    sync::{Arc, Mutex},
};

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, Method, StatusCode},
    response::{IntoResponse, Redirect},
    routing::{delete, get, post},
    Json, Router,
};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::collections::HashMap;
use tower_http::cors::{AllowOrigin, CorsLayer};

type Db = Arc<Mutex<Connection>>;

#[tokio::main]
async fn main() {
    let db_path = std::env::var("SLOP_DB").unwrap_or_else(|_| "slopshop.db".to_string());
    let conn = Connection::open(db_path).expect("open db");
    init_db(&conn);
    let db: Db = Arc::new(Mutex::new(conn));

    // VULN-10 (Security misconfiguration): credentialed CORS that mirrors
    // ANY requesting origin. Combined with cookie auth this lets any website
    // the victim visits make authenticated calls to this API.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::mirror_request())
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/signup", post(signup))
        .route("/api/login", post(login))
        .route("/api/password-reset", post(password_reset))
        .route("/api/logout", post(logout).get(logout_redirect))
        .route("/api/me", get(me))
        .route("/api/products", get(list_products).post(create_product))
        .route("/api/products/:id", get(get_product).delete(delete_product))
        .route("/api/search", get(search))
        .route("/api/orders", post(create_order))
        .route("/api/orders/:id", get(get_order))
        .route("/api/users/:id", get(get_user).put(update_user))
        .route("/api/logs", get(read_log))
        .route("/api/admin/users", get(admin_list_users))
        .route("/api/admin/users/:id", delete(admin_delete_user))
        .layer(cors)
        .with_state(db);

    // Loopback by default; an alternate port can be used for isolated tests.
    let addr = std::env::var("SLOP_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    println!("SlopShop backend (INSECURE v0) listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// ---------------------------------------------------------------------------
// Database setup + synthetic seed data
// ---------------------------------------------------------------------------
fn init_db(conn: &Connection) {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT,
            address TEXT
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            description TEXT,
            price REAL
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            items TEXT,
            total REAL
        );",
    )
    .unwrap();

    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
        .unwrap();
    if count == 0 {
        // VULN-02 (Cryptographic failure): passwords stored in plaintext.
        // Admin is id=1 on purpose so an `' OR '1'='1` login lands on admin.
        conn.execute_batch(
            "INSERT INTO users (username,password,role,address) VALUES
                ('admin','admin123','admin','1 Server Room, Dublin'),
                ('staff','staff123','staff','2 Stockroom Ave, Dublin'),
                ('alice','password123','customer','3 Customer Rd, Cork');
             INSERT INTO products (name,description,price) VALUES
                ('SlopSecurity Free','Basic protection for the hopeful. Real-time scanning that usually runs.',0.00),
                ('SlopSecurity Plus','<b>Ransomware</b> protection, an intelligent firewall, and automatic security updates.',19.99),
                ('SlopSecurity Pro','Everything in Plus, with a private VPN and priority support whenever you need it.',49.99),
                ('SlopSecurity Ultimate','Complete device protection, identity monitoring, and a secure password vault.',99.99);",
        )
        .unwrap();
    }

    // Keep seeded catalogue copy current in existing local synthetic databases.
    // Deliberately does not sanitise product HTML (VULN-07).
    conn.execute_batch(
        "UPDATE products SET description = 'Basic protection for the hopeful. Real-time scanning that usually runs.' WHERE id = 1;
         UPDATE products SET description = '<b>Ransomware</b> shield, a firewall, and a weekly reassuring email.' WHERE id = 2;
         UPDATE products SET description = 'Everything in Plus, plus a VPN and support that is mostly an AI named Dave.' WHERE id = 3;
         UPDATE products SET description = 'Identity monitoring, a password vault, and a very large green checkmark.' WHERE id = 4;",
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// VULN-16 (Account recovery): no identity proof, reset token, or old password.
// ---------------------------------------------------------------------------
async fn password_reset(State(db): State<Db>, Json(body): Json<Value>) -> impl IntoResponse {
    let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    let conn = db.lock().unwrap();
    match conn.execute(
        "UPDATE users SET password = ?1 WHERE username = ?2",
        rusqlite::params![password, username],
    ) {
        Ok(1) => (StatusCode::OK, Json(json!({ "reset": username }))),
        _ => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "unknown username" })),
        ),
    }
}

// ---------------------------------------------------------------------------
// Session helpers
// ---------------------------------------------------------------------------
// VULN-03 (Broken authentication / session): the "session" is just the raw
// user id in a plaintext, non-HttpOnly, unsigned cookie. Anyone can forge
// `session=1` to become admin, and XSS can read it (not HttpOnly).
fn session_user_id(headers: &HeaderMap) -> Option<i64> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(v) = part.strip_prefix("session=") {
            return v.parse::<i64>().ok();
        }
    }
    None
}

fn current_user(conn: &Connection, headers: &HeaderMap) -> Option<(i64, String, String, String)> {
    let id = session_user_id(headers)?;
    conn.query_row(
        "SELECT id, username, password, role FROM users WHERE id = ?1",
        [id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )
    .ok()
}

fn set_session_cookie(id: i64) -> String {
    // Not HttpOnly, not Secure, not signed. All intentional.
    format!("session={id}; Path=/; SameSite=Lax")
}

fn db_error(context: &str, query: &str, e: &rusqlite::Error) -> (StatusCode, Json<Value>) {
    // VULN-09 (Information disclosure): verbose errors echo the raw SQL and
    // the driver message straight back to the client, which greatly assists
    // injection and schema discovery.
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": e.to_string(), "context": context, "query": query })),
    )
}

// ---------------------------------------------------------------------------
// Auth endpoints
// ---------------------------------------------------------------------------
async fn signup(State(db): State<Db>, Json(body): Json<Value>) -> impl IntoResponse {
    let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");
    // VULN-06 (Mass assignment / privilege escalation): the client-supplied
    // `role` is trusted, so anyone can register directly as an admin.
    let role = body
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("customer");

    let conn = db.lock().unwrap();
    // VULN-01 (SQL injection): string-built INSERT.
    let q = format!(
        "INSERT INTO users (username,password,role) VALUES ('{username}','{password}','{role}')"
    );
    match conn.execute(&q, []) {
        Ok(_) => {
            let id = conn.last_insert_rowid();
            (
                StatusCode::OK,
                [(header::SET_COOKIE, set_session_cookie(id))],
                Json(json!({ "id": id, "username": username, "role": role })),
            )
                .into_response()
        }
        Err(e) => db_error("signup", &q, &e).into_response(),
    }
}

async fn login(State(db): State<Db>, Json(body): Json<Value>) -> impl IntoResponse {
    let username = body.get("username").and_then(|v| v.as_str()).unwrap_or("");
    let password = body.get("password").and_then(|v| v.as_str()).unwrap_or("");

    let conn = db.lock().unwrap();
    // VULN-01 (SQL injection): credentials concatenated straight into SQL.
    // `' OR '1'='1' -- ` as the username bypasses authentication.
    // VULN-11 (No rate limiting): unlimited login attempts, no lockout.
    let q = format!(
        "SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
    );
    let row = conn.query_row(&q, [], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
        ))
    });
    match row {
        Ok((id, username, role)) => (
            StatusCode::OK,
            [(header::SET_COOKIE, set_session_cookie(id))],
            Json(json!({ "id": id, "username": username, "role": role })),
        )
            .into_response(),
        Err(rusqlite::Error::QueryReturnedNoRows) => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid credentials" })),
        )
            .into_response(),
        Err(e) => db_error("login", &q, &e).into_response(),
    }
}

async fn logout() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            header::SET_COOKIE,
            "session=; Path=/; Max-Age=0".to_string(),
        )],
        Json(json!({ "ok": true })),
    )
}

// VULN-17 (Open redirect): an unvalidated client URL becomes the Location
// header, so a trusted localhost logout link can lead to a phishing site.
async fn logout_redirect(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let next = params
        .get("next")
        .cloned()
        .unwrap_or_else(|| "http://localhost:4321/".into());
    (
        [(
            header::SET_COOKIE,
            "session=; Path=/; Max-Age=0".to_string(),
        )],
        Redirect::to(&next),
    )
}

async fn me(State(db): State<Db>, headers: HeaderMap) -> impl IntoResponse {
    let conn = db.lock().unwrap();
    match current_user(&conn, &headers) {
        // VULN-09: returns the plaintext password in the profile payload too.
        Some((id, username, password, role)) => (
            StatusCode::OK,
            Json(json!({ "id": id, "username": username, "password": password, "role": role })),
        ),
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "not logged in" })),
        ),
    }
}

// ---------------------------------------------------------------------------
// Product endpoints
// ---------------------------------------------------------------------------
async fn list_products(State(db): State<Db>) -> impl IntoResponse {
    let conn = db.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT id,name,description,price FROM products ORDER BY id")
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "name": r.get::<_, String>(1)?,
                "description": r.get::<_, String>(2)?,
                "price": r.get::<_, f64>(3)?,
            }))
        })
        .unwrap();
    let products: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    Json(json!(products))
}

async fn get_product(State(db): State<Db>, Path(id): Path<String>) -> impl IntoResponse {
    let conn = db.lock().unwrap();
    // VULN-01 (SQL injection): id concatenated into the query.
    let q = format!("SELECT id,name,description,price FROM products WHERE id = {id}");
    match conn.query_row(&q, [], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?,
            "name": r.get::<_, String>(1)?,
            "description": r.get::<_, String>(2)?,
            "price": r.get::<_, f64>(3)?,
        }))
    }) {
        Ok(v) => (StatusCode::OK, Json(v)).into_response(),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))).into_response()
        }
        Err(e) => db_error("get_product", &q, &e).into_response(),
    }
}

async fn create_product(
    State(db): State<Db>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let conn = db.lock().unwrap();
    // VULN-05 (Broken access control): only checks that *someone* is logged in,
    // never that they are staff/admin. Any customer can create products.
    if current_user(&conn, &headers).is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "login required" })),
        )
            .into_response();
    }
    let name = body.get("name").and_then(|v| v.as_str()).unwrap_or("");
    let description = body
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let price = body.get("price").and_then(|v| v.as_f64()).unwrap_or(0.0);
    // VULN-07 (Stored XSS sink): description is stored verbatim and later
    // rendered as raw HTML by the frontend.
    let q = format!(
        "INSERT INTO products (name,description,price) VALUES ('{name}','{description}',{price})"
    );
    match conn.execute(&q, []) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({ "id": conn.last_insert_rowid(), "name": name })),
        )
            .into_response(),
        Err(e) => db_error("create_product", &q, &e).into_response(),
    }
}

async fn delete_product(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let conn = db.lock().unwrap();
    // VULN-05 (Broken access control): any logged-in user can delete products.
    if current_user(&conn, &headers).is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "login required" })),
        )
            .into_response();
    }
    let q = format!("DELETE FROM products WHERE id = {id}");
    match conn.execute(&q, []) {
        Ok(n) => (StatusCode::OK, Json(json!({ "deleted": n }))).into_response(),
        Err(e) => db_error("delete_product", &q, &e).into_response(),
    }
}

async fn search(
    State(db): State<Db>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let q_param = params.get("q").cloned().unwrap_or_default();
    let conn = db.lock().unwrap();
    // VULN-01 (SQL injection): classic UNION-exploitable LIKE search.
    // e.g. ?q=%' UNION SELECT id,username,password,0 FROM users --
    let q = format!("SELECT id,name,description,price FROM products WHERE name LIKE '%{q_param}%'");
    let mut stmt = match conn.prepare(&q) {
        Ok(s) => s,
        Err(e) => return db_error("search", &q, &e).into_response(),
    };
    let rows = stmt.query_map([], |r| {
        Ok(json!({
            "id": r.get::<_, i64>(0)?,
            "name": r.get::<_, String>(1)?,
            "description": r.get::<_, String>(2)?,
            "price": r.get::<_, f64>(3).unwrap_or(0.0),
        }))
    });
    match rows {
        Ok(rows) => {
            let results: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
            // VULN-08 (Reflected XSS): the raw query is echoed back for the
            // frontend to drop into the page unescaped.
            (
                StatusCode::OK,
                Json(json!({ "query": q_param, "results": results })),
            )
                .into_response()
        }
        Err(e) => db_error("search", &q, &e).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Orders
// ---------------------------------------------------------------------------
async fn create_order(
    State(db): State<Db>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let conn = db.lock().unwrap();
    let user = current_user(&conn, &headers);
    let uid = user.as_ref().map(|u| u.0).unwrap_or(0);
    let items = body.get("items").map(|v| v.to_string()).unwrap_or_default();
    // VULN-13 (Price tampering / mass assignment): the server accepts the
    // client-controlled total without looking up product prices or validating
    // that it is non-negative. localStorage and this JSON can be edited freely.
    let total = body.get("total").and_then(|v| v.as_f64()).unwrap_or(0.0);
    // Checkout accepts fake card fields but does not store/transmit them.
    conn.execute(
        "INSERT INTO orders (user_id, items, total) VALUES (?1, ?2, ?3)",
        rusqlite::params![uid, items, total],
    )
    .ok();
    (
        StatusCode::OK,
        Json(json!({ "id": conn.last_insert_rowid(), "total": total })),
    )
}

async fn get_order(State(db): State<Db>, Path(id): Path<i64>) -> impl IntoResponse {
    let conn = db.lock().unwrap();
    // VULN-04 (IDOR): any order is returned by id with no ownership check.
    match conn.query_row(
        "SELECT id,user_id,items,total FROM orders WHERE id = ?1",
        [id],
        |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "user_id": r.get::<_, i64>(1)?,
                "items": r.get::<_, String>(2)?,
                "total": r.get::<_, f64>(3)?,
            }))
        },
    ) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))),
    }
}

// ---------------------------------------------------------------------------
// User + admin endpoints
// ---------------------------------------------------------------------------
async fn get_user(State(db): State<Db>, Path(id): Path<i64>) -> impl IntoResponse {
    let conn = db.lock().unwrap();
    // VULN-04 (IDOR) + VULN-09: any user's full record, including the
    // plaintext password, is returned to anyone with no authentication.
    match conn.query_row(
        "SELECT id,username,password,role,address FROM users WHERE id = ?1",
        [id],
        |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "username": r.get::<_, String>(1)?,
                "password": r.get::<_, String>(2)?,
                "role": r.get::<_, String>(3)?,
                "address": r.get::<_, String>(4).unwrap_or_default(),
            }))
        },
    ) {
        Ok(v) => (StatusCode::OK, Json(v)),
        Err(_) => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))),
    }
}

// VULN-14 (Unauthorised modification + mass assignment): no session,
// ownership, or role check. Anyone can change any address or promote any user.
async fn update_user(
    State(db): State<Db>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    let address = body.get("address").and_then(|v| v.as_str()).unwrap_or("");
    let role = body
        .get("role")
        .and_then(|v| v.as_str())
        .unwrap_or("customer");
    let conn = db.lock().unwrap();
    match conn.execute(
        "UPDATE users SET address = ?1, role = ?2 WHERE id = ?3",
        rusqlite::params![address, role, id],
    ) {
        Ok(1) => (StatusCode::OK, Json(json!({ "updated": id, "role": role }))),
        _ => (StatusCode::NOT_FOUND, Json(json!({ "error": "not found" }))),
    }
}

// VULN-15 (Arbitrary file read): client paths are not validated or confined
// to a log directory. Absolute paths replace the base, and ../ traversal is
// accepted. The localhost-only UI should use harmless synthetic files.
async fn read_log(Query(params): Query<HashMap<String, String>>) -> impl IntoResponse {
    let file = params.get("file").cloned().unwrap_or_default();
    let base = std::env::var("SLOP_RESOURCE_DIR")
        .unwrap_or_else(|_| env!("CARGO_MANIFEST_DIR").to_string());
    let path = std::path::Path::new(&base).join(&file);
    match fs::read_to_string(path) {
        Ok(contents) => (
            StatusCode::OK,
            Json(json!({ "file": file, "contents": contents })),
        ),
        Err(e) => (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": e.to_string(), "file": file })),
        ),
    }
}

async fn admin_list_users(State(db): State<Db>, headers: HeaderMap) -> impl IntoResponse {
    let conn = db.lock().unwrap();
    // VULN-05 (Missing function-level access control): requires only *a*
    // session, not an admin role. Any logged-in customer dumps every user
    // and password. The frontend merely hides the admin link.
    if current_user(&conn, &headers).is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "login required" })),
        )
            .into_response();
    }
    let mut stmt = conn
        .prepare("SELECT id,username,password,role,address FROM users ORDER BY id")
        .unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(json!({
                "id": r.get::<_, i64>(0)?,
                "username": r.get::<_, String>(1)?,
                "password": r.get::<_, String>(2)?,
                "role": r.get::<_, String>(3)?,
                "address": r.get::<_, String>(4).unwrap_or_default(),
            }))
        })
        .unwrap();
    let users: Vec<Value> = rows.filter_map(|r| r.ok()).collect();
    (StatusCode::OK, Json(json!(users))).into_response()
}

async fn admin_delete_user(
    State(db): State<Db>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let conn = db.lock().unwrap();
    // VULN-05 (Missing function-level access control): any logged-in user can
    // delete any account. No CSRF token either (VULN-12).
    if current_user(&conn, &headers).is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "login required" })),
        )
            .into_response();
    }
    conn.execute("DELETE FROM users WHERE id = ?1", [id]).ok();
    (StatusCode::OK, Json(json!({ "deleted": id }))).into_response()
}
