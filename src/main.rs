use anyhow::Result;
use clap::{Parser, ValueEnum};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, VarInt};
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, Error, ServerName};
use std::{convert::Infallible, net::SocketAddr, sync::Arc, time::SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;

#[derive(Copy, Clone, ValueEnum)]
enum Mode {
	Client,
	Server,
}

#[derive(Parser)]
struct Arguments {
	mode: Mode,
	receive_address: SocketAddr,
	send_address: SocketAddr,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<Infallible> {
	let Arguments {
		mode,
		receive_address,
		send_address,
	} = Arguments::parse();

	match mode {
		Mode::Client => client(receive_address, send_address).await,
		Mode::Server => server(receive_address, send_address).await,
	}
}

async fn client(receive_address: SocketAddr, send_address: SocketAddr) -> Result<Infallible> {
	let quic_endpoint = {
		struct TheCertIs100PercentValidHonest;

		impl ServerCertVerifier for TheCertIs100PercentValidHonest {
			fn verify_server_cert(
				&self,
				_: &Certificate,
				_: &[Certificate],
				_: &ServerName,
				_: &mut dyn Iterator<Item = &[u8]>,
				_: &[u8],
				_: SystemTime,
			) -> Result<ServerCertVerified, Error> {
				Ok(ServerCertVerified::assertion())
			}
		}

		let client_config = ClientConfig::new(Arc::new(
			rustls::ClientConfig::builder()
				.with_safe_defaults()
				.with_custom_certificate_verifier(Arc::new(TheCertIs100PercentValidHonest))
				.with_no_client_auth(),
		));

		let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
		endpoint.set_default_client_config(client_config);

		endpoint
	};

	let tcp_listener = TcpListener::bind(receive_address).await?;

	println!("Listening for TCP connections on {receive_address}");

	loop {
		let (tcp_stream, address) = tcp_listener.accept().await?;

		let quic_connection_future = quic_endpoint.connect(send_address, "")?;

		tokio::spawn(async move {
			let tcp_stream = BufStream::new(tcp_stream);

			let task = tokio::spawn(async move {
				println!("[{address}] Connection opened");

				let quic_connection = quic_connection_future.await?;
				let (send_stream, receive_stream) = quic_connection.open_bi().await?;

				proxy_connection(quic_connection, tcp_stream, send_stream, receive_stream).await
			});

			match task.await.unwrap() {
				Ok(_) => {}
				Err(reason) => println!("[{address}] Connection closed, reason: {reason}"),
			}
		});
	}
}

async fn server(receive_address: SocketAddr, send_address: SocketAddr) -> Result<Infallible> {
	let quic_endpoint = {
		let certificate = rcgen::generate_simple_self_signed(vec!["".into()])?;
		let der = certificate.serialize_der()?;
		let private_key = rustls::PrivateKey(certificate.serialize_private_key_der());
		let chain = vec![Certificate(der.clone())];

		let mut server_config = ServerConfig::with_single_cert(chain, private_key)?;
		let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
		transport_config.max_concurrent_uni_streams(0_u8.into());

		Endpoint::server(server_config, receive_address)?
	};

	println!("Listening for QUIC connections on {receive_address}");

	loop {
		let quic_connection = quic_endpoint.accept().await.unwrap();

		let tcp_stream = BufStream::new(TcpStream::connect(send_address).await?);

		tokio::spawn(async move {
			let address = quic_connection.remote_address();

			let task = tokio::spawn(async move {
				println!("[{address}] Connection opened");

				let quic_connection = quic_connection.await?;
				let (send_stream, receive_stream) = quic_connection.accept_bi().await?;

				proxy_connection(quic_connection, tcp_stream, send_stream, receive_stream).await
			});

			match task.await.unwrap() {
				Ok(_) => {}
				Err(reason) => println!("[{address}] Connection closed, reason: {reason}"),
			}
		});
	}
}

async fn proxy_connection(
	quic_connection: Connection,
	mut tcp_stream: BufStream<TcpStream>,
	mut send_stream: SendStream,
	mut receive_stream: RecvStream,
) -> Result<Infallible> {
	let mut buffer = vec![];

	loop {
		select! {
			biased;
			error = quic_connection.closed() => {
				tcp_stream.write_all(&buffer).await?;
				tcp_stream.shutdown().await?;
				quic_connection.close(VarInt::from(0u8), &[]);
				return Err(error.into())
			},
			result = tcp_stream.read_buf(&mut buffer) => {
				// Tokio is lame and doesnt have a future for when the connection is closed like quic does
				// so if there is an error while reading, we'll just assume that the connection has closed.
				if let Err(error) = result {
					tcp_stream.shutdown().await?;
					send_stream.finish().await?;
					quic_connection.close(VarInt::from(0u8), &[]);
					return Err(error.into())
				}

				send_stream.write_all(&buffer).await?;
				buffer.clear();
			}
			chunk = receive_stream.read_chunk(usize::MAX, true) => {
				let chunk = chunk?.unwrap();
				tcp_stream.write_all(&chunk.bytes).await?;
				tcp_stream.flush().await?;
			},
		}
	}
}
