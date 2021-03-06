#![deny(warnings)]

use neqo_crypto::*;

mod handshake;
use crate::handshake::*;

#[test]
fn make_client() {
    init_db("./db");
    let _c = Client::new("server").expect("should create client");
}

#[test]
fn make_server() {
    init_db("./db");
    let _s = Server::new(&["key"]).expect("should create server");
}

#[test]
fn basic() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    println!("client {:p}", &client);
    let mut server = Server::new(&["key"]).expect("should create server");
    println!("server {:p}", &server);

    let (state, bytes) = client.handshake(NOW, &[]).expect("send CH");
    assert!(bytes.len() > 0);
    assert_eq!(state, HandshakeState::InProgress);

    let (state, bytes) = server.handshake(NOW, &bytes[..]).expect("read CH, send SH");
    assert!(bytes.len() > 0);
    assert_eq!(state, HandshakeState::InProgress);

    let (state, bytes) = client.handshake(NOW, &bytes[..]).expect("send CF");
    assert_eq!(bytes.len(), 0);
    assert_eq!(state, HandshakeState::AuthenticationPending);

    client.authenticated();
    assert_eq!(*client.state(), HandshakeState::Authenticated);

    // Calling handshake() again indicates that we're happy with the cert.
    let (state, bytes) = client.handshake(NOW, &[]).expect("send CF");
    assert!(bytes.len() > 0);
    assert_eq!(state, HandshakeState::Complete);

    let client_info = client.info().expect("got info");
    assert_eq!(TLS_VERSION_1_3, client_info.version());
    assert_eq!(TLS_AES_128_GCM_SHA256, client_info.cipher_suite());

    let (state, bytes) = server.handshake(NOW, &bytes[..]).expect("finish");
    assert_eq!(bytes.len(), 0);
    assert_eq!(state, HandshakeState::Complete);

    let server_info = server.info().expect("got info");
    assert_eq!(TLS_VERSION_1_3, server_info.version());
    assert_eq!(TLS_AES_128_GCM_SHA256, server_info.cipher_suite());
}

#[test]
fn raw() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    println!("client {:?}", client);
    let mut server = Server::new(&["key"]).expect("should create server");
    println!("server {:?}", server);

    let (state, client_records) = client.handshake_raw(NOW, None).expect("send CH");
    assert!(client_records.len() > 0);
    assert_eq!(state, HandshakeState::InProgress);

    let client_preinfo = client.preinfo().expect("get preinfo");
    assert_eq!(client_preinfo.version(), None);
    assert_eq!(client_preinfo.cipher_suite(), None);
    assert_eq!(client_preinfo.early_data(), false);
    assert_eq!(client_preinfo.early_data_cipher(), None);
    assert_eq!(client_preinfo.max_early_data(), 0);
    assert_eq!(client_preinfo.alpn(), None);

    let server_records = forward_records(&mut server, client_records).expect("read CH, send SH");
    assert!(server_records.len() > 0);
    assert_eq!(*server.state(), HandshakeState::InProgress);

    let server_preinfo = server.preinfo().expect("get preinfo");
    assert_eq!(server_preinfo.version(), Some(TLS_VERSION_1_3));
    assert_eq!(server_preinfo.cipher_suite(), Some(TLS_AES_128_GCM_SHA256));
    assert_eq!(server_preinfo.early_data(), false);
    assert_eq!(server_preinfo.early_data_cipher(), None);
    assert_eq!(server_preinfo.max_early_data(), 0);
    assert_eq!(server_preinfo.alpn(), None);

    let client_records = forward_records(&mut client, server_records).expect("send CF");
    assert_eq!(client_records.len(), 0);
    assert_eq!(*client.state(), HandshakeState::AuthenticationPending);

    client.authenticated();
    assert_eq!(*client.state(), HandshakeState::Authenticated);

    // Calling handshake() again indicates that we're happy with the cert.
    let (state, client_records) = client.handshake_raw(NOW, None).expect("send CF");
    assert!(client_records.len() > 0);
    assert_eq!(state, HandshakeState::Complete);

    let server_records = forward_records(&mut server, client_records).expect("finish");
    assert_eq!(server_records.len(), 0);
    assert_eq!(*server.state(), HandshakeState::Complete);

    // The client should have one certificate for the server.
    let mut certs = client.peer_certificate().unwrap();
    let cert_vec: Vec<&[u8]> = certs.collect();
    assert_eq!(1, cert_vec.len());

    // The server shouldn't have a client certificate.
    assert!(server.peer_certificate().is_none());
}

#[test]
fn chacha_client() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    client
        .enable_ciphers(&[TLS_CHACHA20_POLY1305_SHA256])
        .expect("ciphers set");

    connect(&mut client, &mut server);

    assert_eq!(
        client.info().unwrap().cipher_suite(),
        TLS_CHACHA20_POLY1305_SHA256
    );
    assert_eq!(
        server.info().unwrap().cipher_suite(),
        TLS_CHACHA20_POLY1305_SHA256
    );
}

#[test]
fn p256_server() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .set_groups(&[TLS_GRP_EC_SECP256R1])
        .expect("groups set");

    connect(&mut client, &mut server);

    assert_eq!(client.info().unwrap().key_exchange(), TLS_GRP_EC_SECP256R1);
    assert_eq!(server.info().unwrap().key_exchange(), TLS_GRP_EC_SECP256R1);
}

#[test]
fn alpn() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    client.set_alpn(&["alpn"]).expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");
    server.set_alpn(&["alpn"]).expect("should set ALPN");

    connect(&mut client, &mut server);

    let expected = Some(String::from("alpn"));
    assert_eq!(expected.as_ref(), client.info().unwrap().alpn());
    assert_eq!(expected.as_ref(), server.info().unwrap().alpn());
}

#[test]
fn alpn_multi() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    client
        .set_alpn(&["dummy", "alpn"])
        .expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .set_alpn(&["alpn", "other"])
        .expect("should set ALPN");

    connect(&mut client, &mut server);

    let expected = Some(String::from("alpn"));
    assert_eq!(expected.as_ref(), client.info().unwrap().alpn());
    assert_eq!(expected.as_ref(), server.info().unwrap().alpn());
}

#[test]
fn alpn_server_pref() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    client
        .set_alpn(&["dummy", "alpn"])
        .expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");
    server
        .set_alpn(&["alpn", "dummy"])
        .expect("should set ALPN");

    connect(&mut client, &mut server);

    let expected = Some(String::from("alpn"));
    assert_eq!(expected.as_ref(), client.info().unwrap().alpn());
    assert_eq!(expected.as_ref(), server.info().unwrap().alpn());
}

#[test]
fn alpn_no_protocol() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    client.set_alpn(&["a"]).expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");
    server.set_alpn(&["b"]).expect("should set ALPN");

    connect_fail(&mut client, &mut server);

    // TODO(mt) check the error code
}

#[test]
fn alpn_client_only() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    client.set_alpn(&["alpn"]).expect("should set ALPN");
    let mut server = Server::new(&["key"]).expect("should create server");

    connect(&mut client, &mut server);

    assert_eq!(None, client.info().unwrap().alpn());
    assert_eq!(None, server.info().unwrap().alpn());
}

#[test]
fn alpn_server_only() {
    init_db("./db");
    let mut client = Client::new("server.example").expect("should create client");
    let mut server = Server::new(&["key"]).expect("should create server");
    server.set_alpn(&["alpn"]).expect("should set ALPN");

    connect(&mut client, &mut server);

    assert_eq!(None, client.info().unwrap().alpn());
    assert_eq!(None, server.info().unwrap().alpn());
}
