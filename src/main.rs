use quinn::{
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
    Endpoint,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use std::{
    error::Error,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync + 'static>> {
    rustls_post_quantum::provider().install_default().unwrap();
    let server_addr = (Ipv4Addr::LOCALHOST, 8080).into();

    let (endpoint, server_cert) = make_server_endpoint(server_addr)?;
    // accept a single connection
    tokio::spawn(async move {
        let incoming_conn = endpoint.accept().await.unwrap();
        let conn = incoming_conn.await.unwrap();
        println!(
            "[server] connection accepted: addr={}",
            conn.remote_address()
        );
        // Dropping all handles associated with a connection implicitly closes it
    });

    let endpoint = make_client_endpoint((Ipv4Addr::UNSPECIFIED, 0).into(), &[&server_cert])?;
    // connect to server
    let connection = endpoint
        .connect(server_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    println!("[client] connected: addr={}", connection.remote_address());

    // Waiting for a stream will complete with an error when the server closes the connection
    let _ = connection.accept_uni().await;

    // Make sure the server has a chance to clean up
    endpoint.wait_idle().await;

    Ok(())
}

pub fn make_client_endpoint(
    bind_addr: SocketAddr,
    server_certs: &[&[u8]],
) -> Result<Endpoint, Box<dyn Error + Send + Sync + 'static>> {
    let mut certs = rustls::RootCertStore::empty();
    for cert in server_certs {
        certs.add(CertificateDer::from(*cert))?;
    }
    let rustls_config = rustls::ClientConfig::builder()
        .with_root_certificates(certs)
        .with_no_client_auth();
    // rustls_config.alpn_protocols = vec![b"h3".to_vec()];

    let client_cfg =
        quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(rustls_config).unwrap()));
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

pub fn make_server_endpoint(
    bind_addr: SocketAddr,
) -> Result<(Endpoint, CertificateDer<'static>), Box<dyn Error + Send + Sync + 'static>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let server_cert = CertificateDer::from(cert.cert);
    let priv_key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![server_cert.clone()], priv_key.into())
                .unwrap(),
        )
        .unwrap(),
    ));

    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());
    // 1273 is OK
    transport_config.min_mtu(1274);

    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok((endpoint, server_cert))
}
