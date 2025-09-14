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
        AuthenticationMethod,
        CommandType,
        ConversionError,
        Reply,
        messages::{
            ClientGreeting,
            Request,
            Response,
            ServerChoice,
        },
    },
};

#[cfg(feature = "tokio")]
pub mod tokio;

#[derive(Debug)]
pub enum ServerError {
    /// An I/O error occured while communicating with the client.
    IoError(std::io::Error),

    /// A protocol-level error occurred (e.g., client sent a malformed message).
    Protocol(ConversionError),

    /// The client did not offer any authentication methods supported by the
    /// server.
    NoAcceptableAuthMethods,

    /// The client failed the authentication process (e.g., wrong password).
    AuthenticationFailed,

    /// The client requested a command that is not supported by the server
    /// (e.g., BIND).
    CommandNotSupported(CommandType),

    /// The server failed to fulfill the client's request after authentication.
    RequestFailed(Reply),
}

impl ServerError {
    /// Returns `true` if the error is related to authentication.
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            ServerError::AuthenticationFailed | ServerError::NoAcceptableAuthMethods
        )
    }
}

impl From<std::io::Error> for ServerError {
    fn from(value: std::io::Error) -> Self {
        ServerError::IoError(value)
    }
}

impl From<ConversionError> for ServerError {
    fn from(value: ConversionError) -> Self {
        ServerError::Protocol(value)
    }
}

/// A generic trait for a SOCKS server.
pub trait Server<S: AsyncRead + AsyncWrite + Unpin, T = ()>: Sized {
    /// Returns a mutable reference to the underlying I/O stream.
    fn stream(&mut self) -> &mut S;

    /// Processes a single client connection through its entire lifecycle:
    /// handshake, authentication, and request handling.
    #[inline]
    async fn serve_client(mut self) -> Result<T, ServerError> {
        let auth_method = self.perform_handshake().await?;
        self.authenticate(auth_method).await?;
        self.handle_request().await
    }

    /// Performs the initial SOCKS5 handshake.
    ///
    /// It reads the client's greeting, selects a supported authentication
    /// method, and sends the choice back to the client.
    ///
    /// ### Note
    ///
    /// In the default implementation, only
    /// [AuthenticationMethod::NO_AUTHENTICATION] is supported. This method
    /// should be overridden to support other authentication methods.
    async fn perform_handshake(&mut self) -> Result<AuthenticationMethod, ServerError> {
        let mut stream = self.stream();

        let greeting = ClientGreeting::read_from(&mut stream).await?;
        let choice = if greeting
            .authentication_methods
            .contains(&AuthenticationMethod::NO_AUTHENTICATION)
        {
            AuthenticationMethod::NO_AUTHENTICATION
        } else {
            return Err(ServerError::NoAcceptableAuthMethods);
        };

        let response = ServerChoice {
            chosen_authentication_method: choice,
        };
        response.write_to(&mut stream).await?;

        Ok(choice)
    }

    /// Performs the authentication process based on the method chosen during
    /// the handshake.
    ///
    /// ### Note
    ///
    /// In the default implementation, only
    /// [AuthenticationMethod::NO_AUTHENTICATION] is handled successfully.
    /// This method should be overridden to implement other authentication
    /// procedures, such as [AuthenticationMethod::USERNAME_PASSWORD].
    async fn authenticate(&mut self, method: AuthenticationMethod) -> Result<(), ServerError> {
        default_authenticate_impl(method).await
    }

    /// Handles the client's request after successful authentication.
    ///
    /// This method reads the client's command request and dispatches it to the
    /// appropriate handler (e.g., `handle_connect`).
    ///
    /// ### Note
    ///
    /// In the default implementation, only [CommandType::CONNECT] is supported.
    async fn handle_request(self) -> Result<T, ServerError> {
        default_handle_request_impl(self).await
    }

    /// Handles the [CommandType::CONNECT] request from the client.
    ///
    /// This method is responsible for connecting to the target address
    /// specified in the request and then relaying data between the client
    /// and the target.
    async fn handle_connect(self, request: Request) -> Result<T, ServerError>;
}

/// The default implementation for the [Server::authenticate] method.
/// Only allows the [AuthenticationMethod::NO_AUTHENTICATION] method.
#[inline]
pub async fn default_authenticate_impl(method: AuthenticationMethod) -> Result<(), ServerError> {
    match method {
        | AuthenticationMethod::NO_AUTHENTICATION => Ok(()),
        | _ => Err(ServerError::NoAcceptableAuthMethods),
    }
}

/// The default implementation for the [Server::handle_request] method.
///
/// Reads the request and dispatches it. Only supports the
/// [CommandType::CONNECT] command.
#[inline]
pub async fn default_handle_request_impl<E: Server<S, T>, S: AsyncRead + AsyncWrite + Unpin, T>(
    mut server: E,
) -> Result<T, ServerError> {
    let mut stream = server.stream();

    let request = Request::read_from(&mut stream).await?;
    match request.command {
        | CommandType::CONNECT => server.handle_connect(request).await,
        | _ => {
            let response = Response::UNSUPPORTED_COMMAND;
            response.write_to(&mut stream).await?;
            Err(ServerError::CommandNotSupported(request.command))
        },
    }
}
