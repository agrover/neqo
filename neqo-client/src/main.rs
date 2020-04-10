// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// #![cfg_attr(feature = "deny-warnings", deny(warnings))]
// #![warn(clippy::use_self)]
#![warn(rust_2018_idioms)]

use neqo_common::{hex, matches, Datagram};
use neqo_crypto::{init, AuthenticationStatus};
use neqo_http3::{self, Header, Http3Client, Http3ClientEvent, Http3State, Output};
use neqo_transport::FixedConnectionIdManager;

use std::cell::RefCell;
use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::process::exit;
use std::rc::Rc;
use std::time::Instant;

use tokio::net::UdpSocket;

use structopt::StructOpt;
use url::{Origin, Url};

#[derive(Debug)]
pub enum ClientError {
    Http3Error(neqo_http3::Error),
    IoError(io::Error),
}

impl From<io::Error> for ClientError {
    fn from(err: io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<neqo_http3::Error> for ClientError {
    fn from(err: neqo_http3::Error) -> Self {
        Self::Http3Error(err)
    }
}

type Res<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, StructOpt)]
#[structopt(
    name = "neqo-client",
    about = "A basic QUIC HTTP/0.9 and HTTP3 client."
)]
pub struct Args {
    #[structopt(short = "a", long, default_value = "h3-27")]
    /// ALPN labels to negotiate.
    ///
    /// This client still only does HTTP3 no matter what the ALPN says.
    alpn: Vec<String>,

    urls: Vec<Url>,

    #[structopt(short = "m", default_value = "GET")]
    method: String,

    #[structopt(short = "h", long, number_of_values = 2)]
    header: Vec<String>,

    #[structopt(name = "max-table-size", short = "t", long, default_value = "128")]
    max_table_size: u64,

    #[structopt(name = "max-blocked-streams", short = "b", long, default_value = "128")]
    max_blocked_streams: u16,

    #[structopt(name = "use-old-http", short = "o", long)]
    /// Use http 0.9 instead of HTTP/3
    use_old_http: bool,

    #[structopt(name = "output-read-data", long)]
    /// Output received data to stdout
    output_read_data: bool,

    #[structopt(name = "output-dir", long)]
    /// Save contents of fetched URLs to a directory
    output_dir: Option<PathBuf>,

    #[structopt(name = "qns-mode", long)]
    /// Enable special behavior for use with QUIC Network Simulator
    qns_mode: bool,
}

trait Handler {
    fn handle(&mut self, args: &Args, client: &mut Http3Client) -> Res<bool>;
}

async fn emit_datagram(socket: &mut UdpSocket, d: Option<Datagram>) {
    if let Some(d) = d {
        let sent = socket.send(&d[..]).await.expect("Error sending datagram");
        if sent != d.len() {
            eprintln!("Unable to send all {} bytes of datagram", d.len());
        }
    }
}

async fn process_loop(
    local_addr: &SocketAddr,
    remote_addr: &SocketAddr,
    socket: &mut UdpSocket,
    client: &mut Http3Client,
    handler: &mut dyn Handler,
    args: &Args,
) -> Res<neqo_http3::Http3State> {
    let buf = &mut [0u8; 2048];
    loop {
        if let Http3State::Closed(..) = client.state() {
            return Ok(client.state());
        }

        let mut exiting = !handler.handle(args, client)?;

        loop {
            let output = client.process_output(Instant::now());
            match output {
                Output::Datagram(dgram) => emit_datagram(socket, Some(dgram)).await,
                Output::Callback(_duration) => {
                    //socket.set_read_timeout(Some(duration)).unwrap();
                    break;
                }
                Output::None => {
                    // Not strictly necessary, since we're about to exit
                    // socket.set_read_timeout(None).unwrap();
                    exiting = true;
                    break;
                }
            }
        }
        client.process_http3(Instant::now());

        if exiting {
            return Ok(client.state());
        }

        match socket.recv(&mut buf[..]).await {
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                // timer expired
                client.process_timer(Instant::now());
            }
            Err(err) => {
                eprintln!("UDP error: {}", err);
                exit(1)
            }
            Ok(sz) => {
                if sz == buf.len() {
                    eprintln!("Received more than {} bytes", buf.len());
                    continue;
                }
                if sz > 0 {
                    let d = Datagram::new(*remote_addr, *local_addr, &buf[..sz]);
                    client.process_input(d, Instant::now());
                    client.process_http3(Instant::now());
                }
            }
        };
    }
}

struct PreConnectHandler {}
impl Handler for PreConnectHandler {
    fn handle(&mut self, _args: &Args, client: &mut Http3Client) -> Res<bool> {
        let authentication_needed = |e| matches!(e, Http3ClientEvent::AuthenticationNeeded);
        if client.events().any(authentication_needed) {
            client.authenticated(AuthenticationStatus::Ok, Instant::now());
        }
        Ok(Http3State::Connected != client.state())
    }
}

#[derive(Default)]
struct PostConnectHandler {
    streams: HashMap<u64, Option<File>>,
}

// This is a bit fancier than actually needed.
impl Handler for PostConnectHandler {
    fn handle(&mut self, args: &Args, client: &mut Http3Client) -> Res<bool> {
        let mut data = vec![0; 4000];
        client.process_http3(Instant::now());
        while let Some(event) = client.next_event() {
            match event {
                Http3ClientEvent::HeaderReady { stream_id } => match self.streams.get(&stream_id) {
                    Some(out_file) => {
                        let headers = client.read_response_headers(stream_id);
                        if out_file.is_none() {
                            println!("READ HEADERS[{}]: {:?}", stream_id, headers);
                        }
                    }
                    None => {
                        println!("Data on unexpected stream: {}", stream_id);
                        return Ok(false);
                    }
                },
                Http3ClientEvent::DataReadable { stream_id } => {
                    let mut stream_done = false;
                    match self.streams.get_mut(&stream_id) {
                        None => {
                            println!("Data on unexpected stream: {}", stream_id);
                            return Ok(false);
                        }
                        Some(out_file) => {
                            let (sz, fin) = client
                                .read_response_data(Instant::now(), stream_id, &mut data)
                                .expect("Read should succeed");

                            if let Some(out_file) = out_file {
                                if sz > 0 {
                                    out_file.write_all(&data[..sz])?;
                                }
                            } else if !args.output_read_data {
                                println!("READ[{}]: {} bytes", stream_id, sz);
                            } else if let Ok(txt) = String::from_utf8(data.clone()) {
                                println!("READ[{}]: {}", stream_id, txt);
                            } else {
                                println!("READ[{}]: 0x{}", stream_id, hex(&data));
                            }

                            if fin {
                                if out_file.is_none() {
                                    println!("<FIN[{}]>", stream_id);
                                }
                                stream_done = true;
                            }
                        }
                    }

                    if stream_done {
                        self.streams.remove(&stream_id);
                        if self.streams.is_empty() {
                            client.close(Instant::now(), 0, "kthxbye!");
                            return Ok(false);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(true)
    }
}

fn to_headers(values: &[impl AsRef<str>]) -> Vec<Header> {
    values
        .iter()
        .scan(None, |state, value| {
            if let Some(name) = state.take() {
                *state = None;
                Some((name, value.as_ref().to_string())) // TODO use a real type
            } else {
                *state = Some(value.as_ref().to_string());
                None
            }
        })
        .collect()
}

async fn client(
    args: &Args,
    mut socket: UdpSocket,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    origin: &str,
    urls: &[Url],
) -> Res<()> {
    let mut client = Http3Client::new(
        origin,
        &args.alpn,
        Rc::new(RefCell::new(FixedConnectionIdManager::new(0))),
        local_addr,
        remote_addr,
        args.max_table_size,
        args.max_blocked_streams,
    )
    .expect("must succeed");
    // Temporary here to help out the type inference engine
    let mut h = PreConnectHandler {};
    process_loop(
        &local_addr,
        &remote_addr,
        &mut socket,
        &mut client,
        &mut h,
        &args,
    )
    .await?;

    let mut h2 = PostConnectHandler::default();

    let mut open_paths = Vec::new();

    for url in urls {
        let client_stream_id = client.fetch(
            &args.method,
            &url.scheme(),
            &url.host_str().unwrap(),
            &url.path(),
            &to_headers(&args.header),
        )?;

        let _ = client.stream_close_send(client_stream_id);

        let out_file = if let Some(ref dir) = args.output_dir {
            let mut out_path = dir.clone();

            let url_path = if url.path() == "/" {
                // If no path is given... call it "root"?
                "root"
            } else {
                // Omit leading slash
                &url.path()[1..]
            };
            out_path.push(url_path);

            if open_paths.contains(&out_path) {
                eprintln!("duplicate path {}", out_path.display());
                continue;
            }

            eprintln!("Saving {} to {:?}", url.clone().into_string(), out_path);

            let f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&out_path)?;

            open_paths.push(out_path);
            Some(f)
        } else {
            None
        };

        h2.streams.insert(client_stream_id, out_file);
    }

    process_loop(
        &local_addr,
        &remote_addr,
        &mut socket,
        &mut client,
        &mut h2,
        &args,
    )
    .await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init();
    let mut args = Args::from_args();

    if args.qns_mode {
        match env::var("TESTCASE") {
            Ok(s) if s == "http3" => {}
            Ok(s) if s == "handshake" || s == "transfer" => {
                args.use_old_http = true;
            }
            Ok(_) => exit(127),
            Err(_) => exit(1),
        }
    }

    let mut urls_by_origin: HashMap<Origin, Vec<Url>> = HashMap::new();
    for url in &args.urls {
        let entry = urls_by_origin.entry(url.origin()).or_default();
        entry.push(url.clone());
    }

    for ((_scheme, host, port), urls) in urls_by_origin.into_iter().filter_map(|(k, v)| match k {
        Origin::Tuple(s, h, p) => Some(((s, h, p), v)),
        Origin::Opaque(x) => {
            eprintln!("Opaque origin {:?}", x);
            None
        }
    }) {
        let remote_addr: SocketAddr = format!("{}:{}", host, port)
            .to_socket_addrs()?
            .nth(1)
            .unwrap();

        //        let remote_addr: SocketAddr = format!("{}:{}", host, port).parse()?;

        let local_addr = if remote_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?;

        let socket = match UdpSocket::bind(local_addr).await {
            Err(e) => {
                eprintln!("Unable to bind UDP socket: {}", e);
                exit(1)
            }
            Ok(s) => s,
        };
        socket
            .connect(&remote_addr)
            .await
            .expect("Unable to connect UDP socket");

        println!(
            "{} Client connecting: {:?} -> {:?}",
            if args.use_old_http { "H9" } else { "H3" },
            socket.local_addr().unwrap(),
            remote_addr
        );

        client(
            &args,
            socket,
            local_addr,
            remote_addr,
            &format!("{}", host),
            &urls,
        )
        .await?;
    }

    Ok(())
}

// use std::env;
// use std::error::Error;
// use std::io::{stdin, Read};
// use std::net::SocketAddr;
// use tokio::net::UdpSocket;

// fn get_stdin_data() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
//     let mut buf = Vec::new();
//     stdin().read_to_end(&mut buf)?;
//     Ok(buf)
// }

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn Error>> {
//     let remote_addr: SocketAddr = env::args()
//         .nth(1)
//         .unwrap_or_else(|| "127.0.0.1:8080".into())
//         .parse()?;

//     // We use port 0 to let the operating system allocate an available port for us.
//     let local_addr: SocketAddr = if remote_addr.is_ipv4() {
//         "0.0.0.0:0"
//     } else {
//         "[::]:0"
//     }
//     .parse()?;

//     let mut socket = UdpSocket::bind(local_addr).await?;
//     const MAX_DATAGRAM_SIZE: usize = 65_507;
//     socket.connect(&remote_addr).await?;
//     let data = get_stdin_data()?;
//     socket.send(&data).await?;
//     let mut data = vec![0u8; MAX_DATAGRAM_SIZE];
//     let len = socket.recv(&mut data).await?;
//     println!(
//         "Received {} bytes:\n{}",
//         len,
//         String::from_utf8_lossy(&data[..len])
//     );

//     Ok(())
// }
