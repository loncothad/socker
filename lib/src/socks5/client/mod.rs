#![allow(async_fn_in_trait)]

use futures::{
    AsyncRead,
    AsyncWrite,
};

use crate::{
    codec::{
        Decoder,
        Encoder,
    },
    socks5::proto::{
        Address,
        AuthenticationMethod,
        CommandType,
        ConversionError,
        Reply,
        messages::{
            ClientGreeting,
            Request,
            Response,
            ServerChoice,
            auth::username_password,
        },
    },
};

#[cfg(feature = "tokio")]
pub mod tokio;

#[derive(Debug)]
pub enum ClientError {
    IoError(std::io::Error),
    Protocol(ConversionError),
    UnsupportedAuthMethod(AuthenticationMethod),
    AuthenticationFailed,
    RequestFailed(Reply),
}

impl From<std::io::Error> for ClientError {
    fn from(value: std::io::Error) -> Self {
        ClientError::IoError(value)
    }
}

impl From<ConversionError> for ClientError {
    fn from(value: ConversionError) -> Self {
        ClientError::Protocol(value)
    }
}

/// A generic trait for a SOCKS5 client.
pub trait Client<T, S: AsyncRead + AsyncWrite + Unpin>: Sized {
    /// Returns a mutable reference to the underlying I/O stream.
    fn stream(&mut self) -> &mut S;

    /// Establishes a connection to a target.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` if the handshake fails, the server requires
    /// authentication, or the connect request is rejected.
    async fn connect_to_target(
        self,
        target_addr: Address,
        target_port: u16,
    ) -> Result<T, ClientError>;

    /// Performs the initial SOCKS5 handshake.
    ///
    /// The client sends a greeting with its supported authentication methods,
    /// and the server replies with its chosen method.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` if there's an I/O error or a protocol error
    /// during the handshake.
    async fn perform_handshake(
        &mut self,
        methods: Box<[AuthenticationMethod]>,
    ) -> Result<AuthenticationMethod, ClientError> {
        let mut stream = self.stream();

        let greeting = ClientGreeting {
            authentication_methods: methods,
        };
        greeting.write_to(&mut stream).await?;

        let choice = ServerChoice::read_from(&mut stream).await?;
        Ok(choice.chosen_authentication_method)
    }

    /// Sends a `CONNECT` request to the SOCKS5 server to establish a proxy
    /// connection.
    ///
    /// On success, the stream is ready to relay data to and from the target.
    ///
    /// # Errors
    ///
    /// Returns a `ClientError` if the server rejects the request or an I/O
    /// error occurs.
    async fn send_connect_request(
        &mut self,
        target_addr: Address,
        target_port: u16,
    ) -> Result<(), ClientError> {
        let mut stream = self.stream();

        let request = Request {
            command: CommandType::CONNECT,
            address: target_addr,
            port:    target_port,
        };
        request.write_to(&mut stream).await?;

        let response = Response::read_from(&mut stream).await?;
        if response.reply != Reply::SUCCESS {
            Err(ClientError::RequestFailed(response.reply))
        } else {
            Ok(())
        }
    }
}

/// The implementation of the [AuthenticationMethod::USERNAME_PASSWORD]
/// exchange.
pub async fn username_password_auth_impl<L: Client<T, S>, T, S: AsyncRead + AsyncWrite + Unpin>(
    client: &mut L,
    username: Box<[u8]>,
    password: Box<[u8]>,
) -> Result<(), ClientError> {
    let mut stream = client.stream();

    let auth_request = username_password::ClientAuthenticationRequest {
        username,
        password,
    };
    auth_request.write_to(&mut stream).await?;

    let auth_response = username_password::ServerResponse::read_from(&mut stream).await?;
    if auth_response.status.is_failure() {
        Err(ClientError::AuthenticationFailed)
    } else {
        Ok(())
    }
}
