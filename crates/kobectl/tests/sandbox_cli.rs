#![cfg(unix)]

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const WAIT: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

type Handler = dyn Fn(Request, &mut TcpStream) + Send + Sync + 'static;

struct Server {
    address: SocketAddr,
    stopped: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Server {
    fn start(handler: impl Fn(Request, &mut TcpStream) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let handler: Arc<Handler> = Arc::new(handler);
        let thread = thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                stream.set_read_timeout(Some(WAIT)).unwrap();
                if let Some(request) = read_request(&mut stream) {
                    handler(request, &mut stream);
                }
            }
        });
        Self {
            address,
            stopped,
            thread: Some(thread),
        }
    }

    fn endpoint(&self) -> String {
        format!("http://{}", self.address)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    let mut received = Vec::new();
    let header_end = loop {
        if let Some(index) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break index + 4;
        }
        let mut buffer = [0u8; 4096];
        let count = stream.read(&mut buffer).ok()?;
        if count == 0 {
            return None;
        }
        received.extend_from_slice(&buffer[..count]);
    };
    let head = std::str::from_utf8(&received[..header_end]).ok()?;
    let mut lines = head.split("\r\n");
    let mut request_line = lines.next()?.split_whitespace();
    let method = request_line.next()?.to_string();
    let path = request_line.next()?.to_string();
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    let length = headers
        .get("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_default();
    while received.len() < header_end + length {
        let mut buffer = [0u8; 4096];
        let count = stream.read(&mut buffer).ok()?;
        if count == 0 {
            return None;
        }
        received.extend_from_slice(&buffer[..count]);
    }
    Some(Request {
        method,
        path,
        headers,
        body: received[header_end..header_end + length].to_vec(),
    })
}

fn reply(stream: &mut TcpStream, status: u16, headers: &[(&str, &str)], body: &str) {
    let reason = match status {
        200 => "OK",
        202 => "Accepted",
        204 => "No Content",
        401 => "Unauthorized",
        403 => "Forbidden",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Response",
    };
    // Best-effort: a client that has already exited is a legitimate outcome in
    // these tests - several deliberately abandon a request mid-flight to prove
    // a signal path - so a closed peer must not panic the server thread and
    // take the harness down with it through Drop's join().
    let mut send = || -> std::io::Result<()> {
        write!(
            stream,
            "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        )?;
        for (name, value) in headers {
            write!(stream, "{name}: {value}\r\n")?;
        }
        write!(stream, "\r\n{body}")?;
        stream.flush()
    };
    let _ = send();
}

fn keyed_lease(body: &[u8]) -> (String, String) {
    let value: Value = serde_json::from_slice(body).unwrap();
    let key = value["idempotencyKey"].as_str().unwrap().to_string();
    let mut hasher = Sha256::new();
    hasher.update((key.len() as u64).to_be_bytes());
    hasher.update(key.as_bytes());
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    (key, format!("sandbox-{}", &digest[..24]))
}

fn lease_body(id: &str, phase: &str) -> String {
    json!({ "id": id, "phase": phase }).to_string()
}

fn execution_body(state: &str, exit_code: Option<i32>) -> String {
    json!({
        "id": "sbxe-test",
        "state": state,
        "exitCode": exit_code,
        "stdout": "out\n",
        "stderr": "err\n",
        "truncated": false
    })
    .to_string()
}

fn spawn_child(endpoint: &str, args: &[&str]) -> (tempfile::TempDir, Child) {
    spawn_child_with_auth(endpoint, "none", args)
}

fn spawn_child_with_auth(endpoint: &str, auth: &str, args: &[&str]) -> (tempfile::TempDir, Child) {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join(".kobe.toml"),
        format!("endpoint = {endpoint:?}\nauth = {auth:?}\n"),
    )
    .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kobe"));
    command
        .current_dir(directory.path())
        .env("HOME", directory.path())
        .env("XDG_CONFIG_HOME", directory.path().join("config"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    (directory, command.spawn().unwrap())
}

fn wait_output(mut child: Child) -> Output {
    let deadline = Instant::now() + WAIT;
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        assert!(Instant::now() < deadline, "child process exceeded {WAIT:?}");
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_output_bounded(mut child: Child, bound: Duration) -> (bool, Output) {
    let deadline = Instant::now() + bound;
    loop {
        if child.try_wait().unwrap().is_some() {
            return (true, child.wait_with_output().unwrap());
        }
        if Instant::now() >= deadline {
            signal(&child, libc::SIGKILL);
            return (false, child.wait_with_output().unwrap());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn signal(child: &Child, value: i32) {
    let result = unsafe { libc::kill(child.id() as i32, value) };
    assert_eq!(result, 0);
}

#[derive(Default)]
struct RunState {
    lease: Option<String>,
    deleted: bool,
    creates: usize,
    executions: usize,
}

fn run_server(
    state: &str,
    exit_code: Option<i32>,
    release_status: u16,
) -> (Server, Arc<Mutex<RunState>>) {
    let shared = Arc::new(Mutex::new(RunState::default()));
    let observed = Arc::clone(&shared);
    let state = state.to_string();
    let server = Server::start(move |request, stream| {
        let mut current = observed.lock().unwrap();
        if request.method == "POST" && request.path == "/v1/sandbox-leases" {
            current.creates += 1;
            let (_, lease) = keyed_lease(&request.body);
            current.lease = Some(lease.clone());
            let location = format!("/v1/sandbox-leases/{lease}");
            reply(
                stream,
                202,
                &[("Location", &location)],
                &lease_body(&lease, "Pending"),
            );
        } else if request.method == "GET" && request.path.starts_with("/v1/sandbox-leases/") {
            let lease = current.lease.clone().unwrap();
            let phase = if current.deleted {
                "Releasing"
            } else {
                "Ready"
            };
            reply(stream, 200, &[], &lease_body(&lease, phase));
        } else if request.method == "POST" && request.path.ends_with("/executions") {
            current.executions += 1;
            reply(stream, 200, &[], &execution_body(&state, exit_code));
        } else if request.method == "DELETE" && request.path.starts_with("/v1/sandbox-leases/") {
            current.deleted = true;
            reply(stream, release_status, &[], "");
        } else {
            reply(stream, 500, &[], "unexpected request");
        }
    });
    (server, shared)
}

#[test]
fn run_uses_one_json_envelope_for_terminal_and_release_outcomes() {
    for (remote_state, remote_exit, release_status, expected_exit, outcome, released) in [
        ("Succeeded", Some(0), 204, 0, "success", true),
        ("Failed", Some(42), 204, 42, "nonzero", true),
        ("TimedOut", None, 204, 125, "timeout", true),
        ("Cancelled", None, 204, 125, "cancelled", true),
        ("Succeeded", Some(0), 503, 0, "success", false),
    ] {
        let (server, requests) = run_server(remote_state, remote_exit, release_status);
        let (_directory, child) = spawn_child(
            &server.endpoint(),
            &[
                "sandbox", "run", "agents", "--output", "json", "--", "/agent",
            ],
        );
        let output = wait_output(child);
        assert_eq!(output.status.code(), Some(expected_exit), "{remote_state}");
        assert!(
            output.stderr.is_empty(),
            "JSON stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let json: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["apiVersion"], "kobe.sandbox/v1");
        assert_eq!(json["outcome"], outcome);
        assert_eq!(json["processExitCode"], expected_exit);
        assert_eq!(json["cleanup"]["released"], released);
        for field in ["released", "phase", "error"] {
            assert!(json["cleanup"].get(field).is_some(), "cleanup: {field}");
        }
        for field in [
            "lease",
            "execution",
            "state",
            "exitCode",
            "stdout",
            "stderr",
            "truncated",
            "signal",
            "error",
        ] {
            assert!(json.get(field).is_some(), "{remote_state}: {field}");
        }
        let requests = requests.lock().unwrap();
        assert_eq!(requests.creates, 1);
        assert_eq!(requests.executions, 1);
        assert!(requests.deleted);
    }
}

#[test]
fn execution_disconnect_still_cleans_up_and_emits_json_only() {
    let shared = Arc::new(Mutex::new(RunState::default()));
    let observed = Arc::clone(&shared);
    let server = Server::start(move |request, stream| {
        let mut current = observed.lock().unwrap();
        if request.method == "POST" && request.path == "/v1/sandbox-leases" {
            current.creates += 1;
            let (_, lease) = keyed_lease(&request.body);
            current.lease = Some(lease.clone());
            let location = format!("/v1/sandbox-leases/{lease}");
            reply(
                stream,
                202,
                &[("Location", &location)],
                &lease_body(&lease, "Pending"),
            );
        } else if request.method == "POST" && request.path.ends_with("/executions") {
            current.executions += 1;
            // Close both bounded execution attempts before response headers.
        } else if request.method == "DELETE" {
            current.deleted = true;
            reply(stream, 204, &[], "");
        } else if request.method == "GET" {
            let lease = current.lease.clone().unwrap();
            let phase = if current.deleted {
                "Releasing"
            } else {
                "Ready"
            };
            reply(stream, 200, &[], &lease_body(&lease, phase));
        }
    });
    let (_directory, child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    let output = wait_output(child);
    assert_eq!(output.status.code(), Some(125));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["outcome"], "disconnect");
    assert_eq!(json["cleanup"]["released"], true);
    let requests = shared.lock().unwrap();
    assert_eq!(requests.executions, 2);
    assert!(requests.deleted);
}

#[test]
fn lost_create_before_headers_reuses_one_key_and_cleans_one_lease() {
    let creates = Arc::new(Mutex::new(Vec::<String>::new()));
    let leases = Arc::new(Mutex::new(HashSet::<String>::new()));
    let deleted = Arc::new(AtomicBool::new(false));
    let recovery_gets = Arc::new(Mutex::new(0usize));
    let expected = Arc::new(Mutex::new(String::new()));
    let create_log = Arc::clone(&creates);
    let semantic = Arc::clone(&leases);
    let released = Arc::clone(&deleted);
    let gets = Arc::clone(&recovery_gets);
    let expected_lease = Arc::clone(&expected);
    let server = Server::start(move |request, stream| {
        if request.method == "POST" && request.path == "/v1/sandbox-leases" {
            let (key, lease) = keyed_lease(&request.body);
            create_log.lock().unwrap().push(key);
            *expected_lease.lock().unwrap() = lease.clone();
            // Both handlers lose response headers before their durable parent
            // is observable. Cleanup must not treat the first recovery 404 as
            // proof of absence while either keyed handler can still commit.
            let committed = Arc::clone(&semantic);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(100));
                committed.lock().unwrap().insert(lease);
            });
        } else if request.method == "POST" && request.path.ends_with("/executions") {
            reply(stream, 200, &[], &execution_body("Succeeded", Some(0)));
        } else if request.method == "DELETE" {
            assert!(
                !semantic.lock().unwrap().is_empty(),
                "DELETE must not precede delayed create visibility"
            );
            released.store(true, Ordering::SeqCst);
            reply(stream, 204, &[], "");
        } else if request.method == "GET" {
            let mut count = gets.lock().unwrap();
            *count += 1;
            let lease = expected_lease.lock().unwrap().clone();
            if !semantic.lock().unwrap().contains(&lease) {
                reply(stream, 404, &[], "");
                return;
            }
            let phase = if released.load(Ordering::SeqCst) {
                "Releasing"
            } else {
                "Ready"
            };
            reply(stream, 200, &[], &lease_body(&lease, phase));
        }
    });
    let (_directory, child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    let output = wait_output(child);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let creates = creates.lock().unwrap();
    assert_eq!(creates.len(), 2);
    assert_eq!(creates[0], creates[1]);
    assert_eq!(leases.lock().unwrap().len(), 1);
    assert!(*recovery_gets.lock().unwrap() >= 3);
    assert!(deleted.load(Ordering::SeqCst));
}

#[test]
fn lost_create_body_recovers_location_without_reposting_and_cleans_up() {
    let creates = Arc::new(Mutex::new(0usize));
    let gets = Arc::new(Mutex::new(0usize));
    let lease = Arc::new(Mutex::new(String::new()));
    let deleted = Arc::new(AtomicBool::new(false));
    let create_count = Arc::clone(&creates);
    let get_count = Arc::clone(&gets);
    let known_lease = Arc::clone(&lease);
    let released = Arc::clone(&deleted);
    let server = Server::start(move |request, stream| {
        if request.method == "POST" && request.path == "/v1/sandbox-leases" {
            *create_count.lock().unwrap() += 1;
            let (_, id) = keyed_lease(&request.body);
            *known_lease.lock().unwrap() = id.clone();
            let location = format!("/v1/sandbox-leases/{id}");
            write!(
                stream,
                "HTTP/1.1 202 Accepted\r\nContent-Length: 200\r\nLocation: {location}\r\nConnection: close\r\n\r\n{{"
            )
            .unwrap();
            stream.flush().unwrap();
        } else if request.method == "GET" {
            let mut count = get_count.lock().unwrap();
            *count += 1;
            let id = known_lease.lock().unwrap().clone();
            let phase = if released.load(Ordering::SeqCst) {
                "Releasing"
            } else if *count == 1 {
                "Pending"
            } else {
                "Ready"
            };
            reply(stream, 200, &[], &lease_body(&id, phase));
        } else if request.method == "POST" && request.path.ends_with("/executions") {
            reply(stream, 200, &[], &execution_body("Succeeded", Some(0)));
        } else if request.method == "DELETE" {
            released.store(true, Ordering::SeqCst);
            reply(stream, 204, &[], "");
        }
    });
    let (_directory, child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    let output = wait_output(child);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(*creates.lock().unwrap(), 1);
    assert!(*gets.lock().unwrap() >= 3); // Location recovery, Ready, Releasing.
    assert!(deleted.load(Ordering::SeqCst));
}

#[test]
fn create_server_failure_settles_a_late_parent_before_cleanup() {
    let lease = Arc::new(Mutex::new(String::new()));
    let visible = Arc::new(AtomicBool::new(false));
    let deleted = Arc::new(AtomicBool::new(false));
    let gets = Arc::new(Mutex::new(0usize));
    let known = Arc::clone(&lease);
    let parent_visible = Arc::clone(&visible);
    let released = Arc::clone(&deleted);
    let recovery_gets = Arc::clone(&gets);
    let server = Server::start(move |request, stream| {
        if request.method == "POST" && request.path == "/v1/sandbox-leases" {
            let (_, id) = keyed_lease(&request.body);
            *known.lock().unwrap() = id;
            // The handler reports failure before its uncertain Kubernetes
            // CREATE is observable to a subsequent GET.
            reply(stream, 503, &[], "checkpoint failed");
        } else if request.method == "DELETE" {
            assert!(
                parent_visible.load(Ordering::SeqCst),
                "cleanup must not accept 404 before the uncertain parent settles"
            );
            released.store(true, Ordering::SeqCst);
            reply(stream, 204, &[], "");
        } else if request.method == "GET" {
            let mut count = recovery_gets.lock().unwrap();
            *count += 1;
            if *count == 1 {
                reply(stream, 404, &[], "");
                return;
            }
            parent_visible.store(true, Ordering::SeqCst);
            let id = known.lock().unwrap().clone();
            let phase = if released.load(Ordering::SeqCst) {
                "Releasing"
            } else {
                "Pending"
            };
            reply(stream, 200, &[], &lease_body(&id, phase));
        } else {
            panic!("create failure must skip execution: {request:?}");
        }
    });
    let (_directory, child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    let output = wait_output(child);
    assert_eq!(output.status.code(), Some(125));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["outcome"], "createError");
    assert_eq!(json["cleanup"]["released"], true);
    assert!(json["lease"].as_str().unwrap().starts_with("sandbox-"));
    assert!(*gets.lock().unwrap() >= 3);
    assert!(visible.load(Ordering::SeqCst));
    assert!(deleted.load(Ordering::SeqCst));
}

#[test]
fn json_parse_errors_use_the_versioned_envelope_and_never_stderr() {
    let calls = Arc::new(Mutex::new(0usize));
    let observed = Arc::clone(&calls);
    let server = Server::start(move |_request, stream| {
        *observed.lock().unwrap() += 1;
        reply(stream, 500, &[], "unexpected");
    });
    for args in [
        vec!["sandbox", "run", "agents", "--output", "json"],
        vec!["--output=json", "sandbox", "run", "agents"],
        vec!["sandbox", "run", "agents", "-o=json"],
        vec!["sandbox", "run", "agents", "-ojson"],
    ] {
        let (_directory, child) = spawn_child(&server.endpoint(), &args);
        let output = wait_output(child);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stderr.is_empty(), "{args:?}");
        let json: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(json["apiVersion"], "kobe.sandbox/v1");
        assert_eq!(json["outcome"], "clientError");
        assert_eq!(json["processExitCode"], 2);
        assert!(json["cleanup"].is_null());
    }
    assert_eq!(*calls.lock().unwrap(), 0);
}

#[test]
fn json_attach_is_refused_and_port_forward_errors_are_machine_events() {
    let calls = Arc::new(Mutex::new(0usize));
    let observed = Arc::clone(&calls);
    let server = Server::start(move |_request, stream| {
        *observed.lock().unwrap() += 1;
        reply(stream, 403, &[], "forward denied");
    });

    let (_directory, child) = spawn_child(
        &server.endpoint(),
        &["sandbox", "attach", "sandbox-test", "--output", "json"],
    );
    let output = wait_output(child);
    assert_eq!(output.status.code(), Some(125));
    assert!(output.stderr.is_empty());
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["apiVersion"], "kobe.sandbox/v1");
    assert_eq!(envelope["outcome"], "clientError");
    assert!(envelope["error"].as_str().unwrap().contains("interactive"));
    assert_eq!(*calls.lock().unwrap(), 0);

    let (_directory, mut child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox",
            "port-forward",
            "sandbox-test",
            "0:http",
            "--output",
            "json",
        ],
    );
    let stdout = child.stdout.take().unwrap();
    let (line_tx, line_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        for _ in 0..2 {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            line_tx.send(line).unwrap();
        }
    });
    let listening: Value = serde_json::from_str(&line_rx.recv_timeout(WAIT).unwrap()).unwrap();
    assert_eq!(listening["event"], "listening");
    let address = listening["listening"].as_str().unwrap();
    let _local = TcpStream::connect(address).unwrap();
    let failure: Value = serde_json::from_str(&line_rx.recv_timeout(WAIT).unwrap()).unwrap();
    assert_eq!(failure["event"], "connectionError");
    assert!(failure["error"].as_str().unwrap().contains("403"));
    signal(&child, libc::SIGTERM);
    let output = wait_output(child);
    reader.join().unwrap();
    assert!(output.stderr.is_empty());
    assert_eq!(*calls.lock().unwrap(), 1);
}

#[test]
fn json_oidc_without_credentials_fails_before_browser_login_or_create() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let observed = Arc::clone(&calls);
    let server = Server::start(move |request, stream| {
        observed.lock().unwrap().push(request.path.clone());
        if request.path == "/.well-known/kunobi-auth" {
            reply(
                stream,
                200,
                &[],
                &json!({
                    "issuer": "https://issuer.invalid",
                    "clientId": "kobe-cli",
                    "audience": "kobe"
                })
                .to_string(),
            );
        } else {
            panic!("noninteractive OIDC must not create: {request:?}");
        }
    });
    let (_directory, child) = spawn_child_with_auth(
        &server.endpoint(),
        "oidc",
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    let output = wait_output(child);
    assert_eq!(output.status.code(), Some(125));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["outcome"], "createError");
    assert!(json["error"].as_str().unwrap().contains("kobe login"));
    assert_eq!(&*calls.lock().unwrap(), &["/.well-known/kunobi-auth"]);
}

#[test]
fn successful_text_run_never_blocks_on_interactive_cleanup_auth() {
    let directory = tempfile::tempdir().unwrap();
    let config_home = directory.path().join("config");
    let issuer_value = Arc::new(Mutex::new(String::new()));
    let provider_calls = Arc::new(Mutex::new(0usize));
    let advertised = Arc::clone(&issuer_value);
    let provider_call_count = Arc::clone(&provider_calls);
    let issuer_server = Server::start(move |request, stream| {
        *provider_call_count.lock().unwrap() += 1;
        assert_eq!(request.path, "/.well-known/openid-configuration");
        let issuer = advertised.lock().unwrap().clone();
        reply(
            stream,
            200,
            &[],
            &json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{issuer}/authorize"),
                "token_endpoint": format!("{issuer}/token"),
                "jwks_uri": format!("{issuer}/jwks"),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"]
            })
            .to_string(),
        );
    });
    let issuer = issuer_server.endpoint();
    *issuer_value.lock().unwrap() = issuer.clone();

    let digest: String = Sha256::digest(issuer.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let token_name = format!("{digest}.json");
    // `dirs::config_dir` follows XDG on Linux and Library/Application Support
    // on macOS. Populate both so this subprocess regression is portable.
    let token_paths: Vec<_> = [
        config_home.join("kunobi/tokens").join(&token_name),
        directory
            .path()
            .join("Library/Application Support/kunobi/tokens")
            .join(&token_name),
        directory
            .path()
            .join(".config/kunobi/tokens")
            .join(&token_name),
    ]
    .into_iter()
    .collect();
    let stored = json!({
        "id_token": "cached-token",
        "refresh_token": null,
        "expires_at": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
            + 3600,
        "issuer": issuer
    })
    .to_string();
    for path in &token_paths {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, &stored).unwrap();
    }

    let deleted = Arc::new(AtomicBool::new(false));
    let release_seen = Arc::clone(&deleted);
    let tokens_to_remove = token_paths.clone();
    let issuer_for_service = issuer.clone();
    let server = Server::start(move |request, stream| {
        if request.path == "/.well-known/kunobi-auth" {
            reply(
                stream,
                200,
                &[],
                &json!({
                    "issuer": issuer_for_service,
                    "clientId": "kobe-cli",
                    "audience": "kobe"
                })
                .to_string(),
            );
        } else if request.method == "POST" && request.path == "/v1/sandbox-leases" {
            let (_, lease) = keyed_lease(&request.body);
            let location = format!("/v1/sandbox-leases/{lease}");
            reply(
                stream,
                202,
                &[("Location", &location)],
                &lease_body(&lease, "Pending"),
            );
        } else if request.method == "GET" && request.path.starts_with("/v1/sandbox-leases/") {
            let lease = request.path.rsplit('/').next().unwrap();
            reply(stream, 200, &[], &lease_body(lease, "Ready"));
        } else if request.method == "POST" && request.path.ends_with("/executions") {
            // Force cleanup auth down the path that would launch an interactive
            // browser login if automatic release used the ordinary text-mode
            // auth helper.
            for path in &tokens_to_remove {
                std::fs::remove_file(path).unwrap();
            }
            reply(stream, 200, &[], &execution_body("Succeeded", Some(0)));
        } else if request.method == "DELETE" {
            release_seen.store(true, Ordering::SeqCst);
            reply(stream, 204, &[], "");
        } else {
            panic!("unexpected cleanup-auth request: {request:?}");
        }
    });
    std::fs::write(
        directory.path().join(".kobe.toml"),
        format!("endpoint = {:?}\nauth = \"oidc\"\n", server.endpoint()),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_kobe"));
    child
        .current_dir(directory.path())
        .env("HOME", directory.path())
        .env("XDG_CONFIG_HOME", &config_home)
        .args(["sandbox", "run", "agents", "--", "/agent"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (completed, output) = wait_output_bounded(child.spawn().unwrap(), Duration::from_secs(8));
    assert!(
        completed,
        "automatic cleanup auth opened an interactive flow"
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "out\n");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.starts_with("err\n"));
    assert!(stderr.contains("OIDC login is required"));
    assert!(!deleted.load(Ordering::SeqCst));
    assert_eq!(
        *provider_calls.lock().unwrap(),
        0,
        "cleanup must fail before interactive OIDC provider discovery"
    );
}

#[test]
fn json_ssh_first_connect_refuses_without_prompting_or_creating() {
    let calls = Arc::new(Mutex::new(Vec::<String>::new()));
    let observed = Arc::clone(&calls);
    let server = Server::start(move |request, stream| {
        observed.lock().unwrap().push(request.path.clone());
        if request.path == "/v1/status" {
            reply(
                stream,
                200,
                &[],
                &json!({"auth":{"methods":[{"type":"ssh","audience":"kobe-test"}]}}).to_string(),
            );
        } else {
            panic!("noninteractive SSH must not create: {request:?}");
        }
    });
    let (_directory, child) = spawn_child_with_auth(
        &server.endpoint(),
        "ssh",
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    let output = wait_output(child);
    assert_eq!(output.status.code(), Some(125));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["outcome"], "createError");
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("rerun in text mode")
    );
    assert_eq!(&*calls.lock().unwrap(), &["/v1/status"]);
}

#[test]
fn sigint_during_pre_post_auth_does_not_start_a_create() {
    let (stage_tx, stage_rx) = mpsc::channel();
    let auth_gate = gate();
    let gate_for_server = Arc::clone(&auth_gate);
    let paths = Arc::new(Mutex::new(Vec::<String>::new()));
    let observed = Arc::clone(&paths);
    let server = Server::start(move |request, _stream| {
        observed.lock().unwrap().push(request.path);
        stage_tx.send(()).unwrap();
        wait_gate(&gate_for_server);
    });
    let (_directory, child) = spawn_child_with_auth(
        &server.endpoint(),
        "oidc",
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    stage_rx.recv_timeout(WAIT).unwrap();
    signal(&child, libc::SIGINT);
    let output = wait_output(child);
    open(&auth_gate);
    assert_eq!(output.status.code(), Some(130));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["outcome"], "signal");
    assert!(json["lease"].is_null());
    assert!(json["cleanup"].is_null());
    assert_eq!(&*paths.lock().unwrap(), &["/.well-known/kunobi-auth"]);
}

fn gate() -> Arc<(Mutex<bool>, Condvar)> {
    Arc::new((Mutex::new(false), Condvar::new()))
}

fn open(gate: &Arc<(Mutex<bool>, Condvar)>) {
    let (lock, notify) = &**gate;
    *lock.lock().unwrap() = true;
    notify.notify_all();
}

fn wait_gate(gate: &Arc<(Mutex<bool>, Condvar)>) {
    let (lock, notify) = &**gate;
    let _guard = notify
        .wait_while(lock.lock().unwrap(), |opened| !*opened)
        .unwrap();
}

#[test]
fn sigint_before_create_response_waits_for_cleanup_and_exits_130() {
    let (stage_tx, stage_rx) = mpsc::channel();
    let response_gate = gate();
    let release = Arc::new(AtomicBool::new(false));
    let gate_for_server = Arc::clone(&response_gate);
    let released = Arc::clone(&release);
    let server = Server::start(move |request, stream| {
        if request.method == "POST" && request.path == "/v1/sandbox-leases" {
            let (_, lease) = keyed_lease(&request.body);
            stage_tx.send(()).unwrap();
            wait_gate(&gate_for_server);
            let location = format!("/v1/sandbox-leases/{lease}");
            reply(
                stream,
                202,
                &[("Location", &location)],
                &lease_body(&lease, "Pending"),
            );
        } else if request.method == "DELETE" {
            released.store(true, Ordering::SeqCst);
            reply(stream, 204, &[], "");
        } else if request.method == "GET" {
            let id = request.path.rsplit('/').next().unwrap();
            reply(stream, 200, &[], &lease_body(id, "Releasing"));
        } else {
            panic!("signal during create must skip execution: {request:?}");
        }
    });
    let (_directory, child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    stage_rx.recv_timeout(WAIT).unwrap();
    signal(&child, libc::SIGINT);
    open(&response_gate);
    let output = wait_output(child);
    assert_eq!(output.status.code(), Some(130));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["outcome"], "signal");
    assert_eq!(json["signal"], "SIGINT");
    assert_eq!(json["cleanup"]["released"], true);
    assert!(release.load(Ordering::SeqCst));
}

#[test]
fn queued_second_signal_cannot_skip_the_release_request() {
    let (stage_tx, stage_rx) = mpsc::channel();
    let response_gate = gate();
    let gate_for_server = Arc::clone(&response_gate);
    let deleted = Arc::new(AtomicBool::new(false));
    let released = Arc::clone(&deleted);
    // Hold the release observation open. Without this the assertions below
    // race: if the whole release future completes before the queued second
    // signal is picked up, reporting `released: true` is honest, and the
    // unconfirmed path this test exists to cover never runs.
    let observation_gate = gate();
    let gate_for_observation = Arc::clone(&observation_gate);
    let observing = Arc::clone(&deleted);
    let server = Server::start(move |request, stream| {
        if request.method == "POST" && request.path == "/v1/sandbox-leases" {
            let (_, lease) = keyed_lease(&request.body);
            stage_tx.send(()).unwrap();
            wait_gate(&gate_for_server);
            let location = format!("/v1/sandbox-leases/{lease}");
            reply(
                stream,
                202,
                &[("Location", &location)],
                &lease_body(&lease, "Pending"),
            );
        } else if request.method == "DELETE" {
            released.store(true, Ordering::SeqCst);
            reply(stream, 204, &[], "");
        } else if request.method == "GET" {
            // Only the post-DELETE observation is held; a readiness poll
            // before it must still answer.
            if observing.load(Ordering::SeqCst) {
                wait_gate(&gate_for_observation);
            }
            let id = request.path.rsplit('/').next().unwrap();
            reply(stream, 200, &[], &lease_body(id, "Releasing"));
        } else {
            panic!("signals before create response must skip execution: {request:?}");
        }
    });
    let (_directory, child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    stage_rx.recv_timeout(WAIT).unwrap();
    signal(&child, libc::SIGINT);
    signal(&child, libc::SIGTERM);
    open(&response_gate);
    let output = wait_output(child);
    open(&observation_gate);
    assert_eq!(output.status.code(), Some(130));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["signal"], "SIGINT");
    assert_eq!(json["cleanup"]["released"], false);
    assert!(
        json["cleanup"]["error"]
            .as_str()
            .unwrap()
            .contains("second SIGTERM")
    );
    assert!(
        deleted.load(Ordering::SeqCst),
        "the queued second signal must not skip DELETE"
    );
}

#[test]
fn sigterm_during_execution_releases_and_exits_143() {
    let (stage_tx, stage_rx) = mpsc::channel();
    let execution_gate = gate();
    let released = Arc::new(AtomicBool::new(false));
    let gate_for_server = Arc::clone(&execution_gate);
    let release = Arc::clone(&released);
    let server = Server::start(move |request, stream| {
        if request.method == "POST" && request.path == "/v1/sandbox-leases" {
            let (_, lease) = keyed_lease(&request.body);
            let location = format!("/v1/sandbox-leases/{lease}");
            reply(
                stream,
                202,
                &[("Location", &location)],
                &lease_body(&lease, "Pending"),
            );
        } else if request.method == "GET" {
            let id = request.path.rsplit('/').next().unwrap();
            let phase = if release.load(Ordering::SeqCst) {
                "Releasing"
            } else {
                "Ready"
            };
            reply(stream, 200, &[], &lease_body(id, phase));
        } else if request.method == "POST" && request.path.ends_with("/executions") {
            stage_tx.send(()).unwrap();
            wait_gate(&gate_for_server);
            let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        } else if request.method == "DELETE" {
            release.store(true, Ordering::SeqCst);
            reply(stream, 204, &[], "");
        }
    });
    let (_directory, child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    stage_rx.recv_timeout(WAIT).unwrap();
    signal(&child, libc::SIGTERM);
    open(&execution_gate);
    let output = wait_output(child);
    assert_eq!(output.status.code(), Some(143));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["signal"], "SIGTERM");
    assert_eq!(json["cleanup"]["released"], true);
    assert!(released.load(Ordering::SeqCst));
}

#[test]
fn sigint_during_release_keeps_waiting_for_observable_releasing() {
    let (stage_tx, stage_rx) = mpsc::channel();
    let release_gate = gate();
    let gate_for_server = Arc::clone(&release_gate);
    let gets = Arc::new(Mutex::new(0usize));
    let observed_gets = Arc::clone(&gets);
    let server = Server::start(move |request, stream| {
        if request.method == "POST" && request.path == "/v1/sandbox-leases" {
            let (_, lease) = keyed_lease(&request.body);
            let location = format!("/v1/sandbox-leases/{lease}");
            reply(
                stream,
                202,
                &[("Location", &location)],
                &lease_body(&lease, "Pending"),
            );
        } else if request.method == "POST" && request.path.ends_with("/executions") {
            reply(stream, 200, &[], &execution_body("Succeeded", Some(0)));
        } else if request.method == "DELETE" {
            reply(stream, 204, &[], "");
        } else if request.method == "GET" {
            let mut gets = observed_gets.lock().unwrap();
            *gets += 1;
            let id = request.path.rsplit('/').next().unwrap();
            if *gets == 1 {
                reply(stream, 200, &[], &lease_body(id, "Ready"));
            } else {
                stage_tx.send(()).unwrap();
                drop(gets);
                wait_gate(&gate_for_server);
                reply(stream, 200, &[], &lease_body(id, "Releasing"));
            }
        }
    });
    let (_directory, mut child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    stage_rx.recv_timeout(WAIT).unwrap();
    signal(&child, libc::SIGINT);
    thread::sleep(Duration::from_millis(100));
    assert!(
        child.try_wait().unwrap().is_none(),
        "the first signal must not skip observable release"
    );
    open(&release_gate);
    let output = wait_output(child);
    assert_eq!(output.status.code(), Some(130));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["signal"], "SIGINT");
    assert_eq!(json["cleanup"]["released"], true);
    assert_eq!(json["cleanup"]["phase"], "Releasing");
}

#[test]
fn first_signal_during_release_keeps_waiting_and_second_signal_stops_the_wait() {
    let (stage_tx, stage_rx) = mpsc::channel();
    let release_gate = gate();
    let gate_for_server = Arc::clone(&release_gate);
    let gets = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed_gets = Arc::clone(&gets);
    let server = Server::start(move |request, stream| {
        if request.method == "POST" && request.path == "/v1/sandbox-leases" {
            let (_, lease) = keyed_lease(&request.body);
            let location = format!("/v1/sandbox-leases/{lease}");
            reply(
                stream,
                202,
                &[("Location", &location)],
                &lease_body(&lease, "Pending"),
            );
        } else if request.method == "POST" && request.path.ends_with("/executions") {
            reply(stream, 200, &[], &execution_body("Succeeded", Some(0)));
        } else if request.method == "DELETE" {
            reply(stream, 204, &[], "");
        } else if request.method == "GET" && request.path.contains("sandbox-") {
            if observed_gets.fetch_add(1, Ordering::SeqCst) == 0 {
                let id = request.path.rsplit('/').next().unwrap();
                reply(stream, 200, &[], &lease_body(id, "Ready"));
            } else {
                stage_tx.send(()).unwrap();
                wait_gate(&gate_for_server);
            }
        }
    });
    let (_directory, mut child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox", "run", "agents", "--output", "json", "--", "/agent",
        ],
    );
    stage_rx.recv_timeout(WAIT).unwrap();
    signal(&child, libc::SIGINT);
    thread::sleep(Duration::from_millis(100));
    assert!(
        child.try_wait().unwrap().is_none(),
        "first signal must keep waiting for cleanup"
    );
    signal(&child, libc::SIGTERM);
    let output = wait_output(child);
    open(&release_gate);
    assert_eq!(output.status.code(), Some(130));
    assert!(output.stderr.is_empty());
    let json: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["signal"], "SIGINT");
    assert_eq!(json["cleanup"]["released"], false);
    assert!(
        json["cleanup"]["error"]
            .as_str()
            .unwrap()
            .contains("second SIGTERM")
    );
}

#[derive(Default)]
struct LogState {
    calls: usize,
    paths: Vec<String>,
}

fn log_window(state: &str, stdout: Value, stderr: Value) -> String {
    json!({ "id": "sbxe-test", "state": state, "stdout": stdout, "stderr": stderr }).to_string()
}

#[test]
fn logs_follow_separates_streams_drains_terminal_stalls_and_preserves_offsets() {
    let shared = Arc::new(Mutex::new(LogState::default()));
    let observed = Arc::clone(&shared);
    let server = Server::start(move |request, stream| {
        assert!(request.headers.contains_key("host"));
        let mut state = observed.lock().unwrap();
        state.paths.push(request.path.clone());
        state.calls += 1;
        let body = match state.calls {
            1 => log_window(
                "Running",
                json!({"data":"out-1\n","nextOffset":6,"more":false,"truncated":false}),
                json!({"data":"err-1\n","nextOffset":6,"more":false,"truncated":false}),
            ),
            2 => log_window(
                "Running",
                json!({"data":"","nextOffset":6,"more":true,"truncated":false}),
                json!({"data":"","nextOffset":6,"more":false,"truncated":false}),
            ),
            3 => log_window(
                "Succeeded",
                json!({"data":"out-2\n","nextOffset":12,"more":true,"truncated":false}),
                json!({"data":"err-2\n","nextOffset":12,"more":false,"truncated":true}),
            ),
            _ => log_window(
                "Succeeded",
                json!({"data":"","nextOffset":12,"more":false,"truncated":false}),
                json!({"data":"","nextOffset":12,"more":false,"truncated":false}),
            ),
        };
        reply(stream, 200, &[], &body);
    });
    let (_directory, child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox",
            "logs",
            "sandbox-test",
            "--execution",
            "sbxe-test",
            "--follow",
        ],
    );
    let output = wait_output(child);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "out-1\nout-2\n");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.starts_with("err-1\nerr-2\n"));
    assert!(stderr.contains("truncated"));
    let state = shared.lock().unwrap();
    assert_eq!(state.calls, 4);
    assert!(state.paths[1].ends_with("stdoutOffset=6&stderrOffset=6"));
    assert!(state.paths[2].ends_with("stdoutOffset=6&stderrOffset=6"));
    assert!(state.paths[3].ends_with("stdoutOffset=12&stderrOffset=12"));
}

#[test]
fn logs_follow_retries_disconnect_once_at_the_same_offsets_and_auth_is_terminal() {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&paths);
    let server = Server::start(move |request, stream| {
        let mut paths = observed.lock().unwrap();
        paths.push(request.path);
        if paths.len() == 1 {
            return;
        }
        let body = log_window(
            "Succeeded",
            json!({"data":"done\n","nextOffset":5,"more":false,"truncated":false}),
            json!({"data":"","nextOffset":0,"more":false,"truncated":false}),
        );
        reply(stream, 200, &[], &body);
    });
    let (_directory, child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox",
            "logs",
            "sandbox-test",
            "--execution",
            "sbxe-test",
            "--follow",
        ],
    );
    let output = wait_output(child);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "done\n");
    let paths = paths.lock().unwrap();
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[0], paths[1]);

    for status in [401, 403] {
        let calls = Arc::new(Mutex::new(0usize));
        let observed = Arc::clone(&calls);
        let server = Server::start(move |_request, stream| {
            *observed.lock().unwrap() += 1;
            reply(stream, status, &[], "no");
        });
        let (_directory, child) = spawn_child(
            &server.endpoint(),
            &[
                "sandbox",
                "logs",
                "sandbox-test",
                "--execution",
                "sbxe-test",
                "--follow",
                "--output",
                "json",
            ],
        );
        let output = wait_output(child);
        assert_eq!(output.status.code(), Some(125));
        assert!(output.stderr.is_empty());
        assert_eq!(*calls.lock().unwrap(), 1, "HTTP {status} must not retry");
    }
}

#[test]
fn logs_follow_retries_a_truncated_response_body_at_the_same_offsets() {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&paths);
    let server = Server::start(move |request, stream| {
        let mut paths = observed.lock().unwrap();
        paths.push(request.path);
        if paths.len() == 1 {
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: 200\r\nConnection: close\r\n\r\n{{"
            )
            .unwrap();
            stream.flush().unwrap();
            return;
        }
        let body = log_window(
            "Succeeded",
            json!({"data":"once\n","nextOffset":5,"more":false,"truncated":false}),
            json!({"data":"","nextOffset":0,"more":false,"truncated":false}),
        );
        reply(stream, 200, &[], &body);
    });
    let (_directory, child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox",
            "logs",
            "sandbox-test",
            "--execution",
            "sbxe-test",
            "--follow",
        ],
    );
    let output = wait_output(child);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(String::from_utf8(output.stdout).unwrap(), "once\n");
    let paths = paths.lock().unwrap();
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[0], paths[1]);
}

#[test]
fn logs_follow_flushes_each_ndjson_record_before_the_next_poll_finishes() {
    let (stage_tx, stage_rx) = mpsc::channel();
    let second_gate = gate();
    let gate_for_server = Arc::clone(&second_gate);
    let calls = Arc::new(Mutex::new(0usize));
    let observed = Arc::clone(&calls);
    let server = Server::start(move |_request, stream| {
        let mut calls = observed.lock().unwrap();
        *calls += 1;
        if *calls == 1 {
            let body = log_window(
                "Running",
                json!({"data":"visible","nextOffset":7,"more":false,"truncated":false}),
                json!({"data":"","nextOffset":0,"more":false,"truncated":false}),
            );
            reply(stream, 200, &[], &body);
        } else {
            stage_tx.send(()).unwrap();
            drop(calls);
            wait_gate(&gate_for_server);
            let body = log_window(
                "Succeeded",
                json!({"data":"","nextOffset":7,"more":false,"truncated":false}),
                json!({"data":"","nextOffset":0,"more":false,"truncated":false}),
            );
            reply(stream, 200, &[], &body);
        }
    });
    let (_directory, mut child) = spawn_child(
        &server.endpoint(),
        &[
            "sandbox",
            "logs",
            "sandbox-test",
            "--execution",
            "sbxe-test",
            "--follow",
            "--output",
            "json",
        ],
    );
    let stdout = child.stdout.take().unwrap();
    let (line_tx, line_rx) = mpsc::channel();
    let reader = thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        line_tx.send(line).unwrap();
        let mut remainder = String::new();
        reader.read_to_string(&mut remainder).unwrap();
    });
    stage_rx.recv_timeout(WAIT).unwrap();
    let line = line_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("the first NDJSON record must be pipe-visible before the next response");
    assert_eq!(
        serde_json::from_str::<Value>(&line).unwrap()["stdout"]["data"],
        "visible"
    );
    open(&second_gate);
    let output = wait_output(child);
    reader.join().unwrap();
    assert_eq!(output.status.code(), Some(0));
}
