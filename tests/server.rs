//! Module for the mock bird server we use for testing.
//!
//! Start a mock server using [MockServer::start_server], and use the
//! `Ok(server)` returned to connect clients to it via `server.unix_socket`

use std::{
    io::Result,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::{UnixListener, UnixStream},
    sync::Mutex,
};

/// A mock bird server that we use to test
pub struct MockServer {
    pub unix_socket: String,
    client_count: Arc<Mutex<usize>>,
}

impl MockServer {
    /// Starts a server, and no matter what command the client requests, dumps
    /// `reponse` to it (after the request has been made). Returns the instance
    /// of this server, from which the unix socket can be accessed by the client.
    ///
    /// To give no response, just set `reponse` to an empty str.
    ///
    /// `delay_ms` introduces random delays in response, to test client buffering.
    /// Set to 0 to disable.
    pub async fn start_server(response: &str, delay_ms: u64) -> Result<MockServer> {
        let socket_name = format!("/tmp/test-birdc-{}.ctl", rand::random::<u32>());
        let path = Path::new(&socket_name);
        if path.exists() {
            let _ = std::fs::remove_file(path);
        }

        let count_main = Arc::new(Mutex::new(0));
        let count_looper = count_main.clone();

        let listener = UnixListener::bind(path)?;
        let response = response.to_owned();
        tokio::spawn(async move {
            loop {
                let stream = listener
                    .accept()
                    .await
                    .expect("error in accepting new connection");
                Self::process_client(stream.0, &response, delay_ms).await;
                // increment client clount and notify
                let mut count = count_looper.lock().await;
                *count += 1;
            }
        });

        Ok(MockServer {
            unix_socket: path.to_str().unwrap().to_string(),
            client_count: count_main,
        })
    }

    /// Process this client.
    ///
    /// This does the following things:
    /// 1. Write welcome greeting
    /// 2. If `response` is not empty, read a request from the client
    /// 3. If `response` is not empty, write `response` to the client
    async fn process_client(stream: UnixStream, response: &str, delay_ms: u64) {
        Self::write_to_client(&stream, GREETING).await;
        log::trace!("server: written greeting to client");

        if !response.is_empty() {
            // wait until we've received a command from the client
            let mut buffer = [0; 128];
            loop {
                stream
                    .readable()
                    .await
                    .expect("server: failed to wait on stream reading");
                match stream.try_read(&mut buffer) {
                    Ok(0) => {
                        panic!("server: premature EOF");
                    }
                    Ok(count) => {
                        if buffer[count - 1] == b'\n' {
                            log::trace!(
                                "server: received request {}. sending response",
                                String::from_utf8_lossy(&buffer[..count]).trim()
                            );
                            if delay_ms > 0 {
                                for ref c in split_content(response) {
                                    log::trace!("sending chunk: {}", c);
                                    Self::write_to_client(&stream, c).await;
                                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                                }
                                break;
                            } else {
                                Self::write_to_client(&stream, response).await;
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        if err.kind() != std::io::ErrorKind::WouldBlock {
                            panic!("server: encountered IO error: {}", err);
                        }
                    }
                }
            }
        }
    }

    /// Helper method to write `content` to `stream` client in an async way
    async fn write_to_client(stream: &UnixStream, content: &str) {
        stream
            .writable()
            .await
            .expect("failed to wait on stream writing");
        stream
            .try_write(content.as_bytes())
            .expect("failed to write");
        log::trace!("server: written content of {} bytes", content.len());
    }

    /// Wait at max until `timout_secs` for the server to have received `num_clients`
    /// connections.
    pub async fn wait_until(&self, num_clients: usize, timeout_secs: u64) {
        let start = Instant::now();
        let duration = Duration::from_secs(timeout_secs);
        loop {
            let count = *self.client_count.lock().await;
            if count >= num_clients {
                return;
            }
            let expired = Instant::now().duration_since(start) > duration;
            assert!(
                !expired,
                "timed out waiting for {} client connections",
                num_clients
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// Helper method that takes in `s` as a multiline string, and trims off the indent
/// that might have come due to the text editor.
pub fn heredoc(s: &str) -> String {
    let indent = if let Some(line2) = s.split('\n').nth(1) {
        line2.find(char::is_alphanumeric).unwrap_or(0)
    } else {
        0
    };
    s.lines()
        .map(|x| (if x.starts_with(' ') { &x[indent..] } else { x }).into())
        .collect::<Vec<String>>()
        .join("\n")
}

/// Splits up the content into chunks
fn split_content(content: &str) -> Vec<String> {
    let pos1 = content.len() / 3;
    let pos2 = content.len() / 2;
    vec![
        content[..pos1].into(),
        content[pos1..pos2].into(),
        content[pos2..].into(),
    ]
}

/// The welcome string we sent to each client on connection
const GREETING: &str = "0001 BIRD 2.0.7 ready.\n";
