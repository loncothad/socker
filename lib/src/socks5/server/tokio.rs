use std::{
    io::Result as IoResult,
    sync::Arc,
};

use tokio::net::{
    TcpListener,
    TcpStream,
    ToSocketAddrs,
};
use tokio_util::compat::{
    Compat,
    TokioAsyncReadCompatExt,
};

#[allow(unused, reason = "docs")]
use super::CommandType;
use crate::{
    codec::{
        Decoder,
        Encoder,
    },
    socks5::{
        proto::{
            Address,
            AuthenticationMethod,
            Reply,
            messages::{
                Request,
                Response,
                auth::username_password,
            },
        },
        server::{
            Server,
            ServerError,
            default_authenticate_impl,
        },
    },
};

type CredentialsHolder = Arc<(Box<[u8]>, Box<[u8]>)>;

/// A Tokio-based SOCKS5 server listener.
pub struct Socks5Listener {
    listener:    TcpListener,
    credentials: CredentialsHolder,
}

impl Socks5Listener {
    /// # Errors
    ///
    /// Returns an [std::io::Result] error if the listener fails to bind to the
    /// address.
    pub async fn bind<A: ToSocketAddrs>(addr: A, credentials: CredentialsHolder) -> IoResult<Self> {
        let listener = TcpListener::bind(addr).await?;

        Ok(Self {
            listener,
            credentials,
        })
    }

    /// Starts the main server loop, accepting and handling connections
    /// indefinitely.
    pub async fn run(&self) -> IoResult<()> {
        loop {
            let (stream, _peer_addr) = self.listener.accept().await?;
            let creds = self.credentials.clone();
            tokio::spawn(async move {
                let _ = Socks5Server::new(stream, creds).serve_client().await;
            });
        }
    }
}

/// A Tokio-based SOCKS server for handling a single client connection.
///
/// The [Server] implementation for this struct provides these capabilities:
/// * [AuthenticationMethod::USERNAME_PASSWORD] authentication;
/// * [CommandType::CONNECT] command support.
pub struct Socks5Server {
    stream:      Compat<TcpStream>,
    credentials: CredentialsHolder,
}

impl Socks5Server {
    pub fn new(stream: TcpStream, credentials: CredentialsHolder) -> Self {
        Self {
            stream: stream.compat(),
            credentials,
        }
    }
}

impl Server<Compat<TcpStream>> for Socks5Server {
    #[inline]
    fn stream(&mut self) -> &mut Compat<TcpStream> {
        &mut self.stream
    }

    /// Handles a [CommandType::CONNECT] request from a SOCKS client.
    ///
    /// # Errors
    /// Returns a [ServerError] if it fails to connect to the target or if there
    /// are I/O errors during communication.
    async fn handle_connect(mut self, request: Request) -> Result<(), super::ServerError> {
        let port = request.port;

        let target_stream = match &request.address {
            | Address::Ipv4(addr) => TcpStream::connect((*addr, port)).await,
            | Address::Ipv6(addr) => TcpStream::connect((*addr, port)).await,
            | Address::Domain(domain) => {
                // SAFETY: we don't really care about the String compliance there
                //         as the protocol accepts any byte array - yet,
                //         the `connect` doesn't accept [u8] as an argument
                //         so we use unsafe
                let domain = unsafe { str::from_utf8_unchecked(&domain) };
                TcpStream::connect((domain, port)).await
            },
        };

        let target_stream = match target_stream {
            | Ok(s) => s,
            | Err(_) => {
                let response = Response::HOST_UNREACHABLE;
                response.write_to(self.stream()).await?;
                return Err(ServerError::RequestFailed(Reply::HOST_UNREACHABLE));
            },
        };

        let response = Response {
            reply:   Reply::SUCCESS,
            address: request.address,
            port:    request.port,
        };
        response.write_to(self.stream()).await?;

        let (mut client_reader, mut client_writer) = tokio::io::split(self.stream.into_inner());
        let (mut target_reader, mut target_writer) = tokio::io::split(target_stream);
        let client_to_target = tokio::io::copy(&mut client_reader, &mut target_writer);
        let target_to_client = tokio::io::copy(&mut target_reader, &mut client_writer);

        tokio::select! {
            _ = client_to_target => {},
            _ = target_to_client => {},
        }

        Ok(())
    }

    /// Overrides the default `authenticate` method to support
    /// [AuthenticationMethod::USERNAME_PASSWORD] auth alongside with the
    /// [AuthenticationMethod::NO_AUTHENTICATION].
    ///
    /// # Errors
    ///
    /// Returns [ServerError::AuthenticationFailed] if the client's credentials
    /// do not match the server's credentials.
    async fn authenticate(
        &mut self,
        method: AuthenticationMethod,
    ) -> Result<(), super::ServerError> {
        match method {
            | AuthenticationMethod::USERNAME_PASSWORD => {
                let auth_request =
                    username_password::ClientAuthenticationRequest::read_from(self.stream())
                        .await?;

                if auth_request.username != self.credentials.0
                    || auth_request.password != self.credentials.1
                {
                    return Err(ServerError::AuthenticationFailed);
                }

                Ok(())
            },
            | _ => default_authenticate_impl(method).await,
        }
    }
}
