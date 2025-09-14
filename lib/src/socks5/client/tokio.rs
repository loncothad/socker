use std::sync::Arc;

use tokio::net::TcpStream;
use tokio_util::compat::{
    Compat,
    TokioAsyncReadCompatExt,
};

use crate::socks5::{
    client::{
        Client,
        ClientError,
        username_password_auth_impl,
    },
    proto::{
        Address,
        AuthenticationMethod,
    },
};

type CredentialsHolder = Arc<(Box<[u8]>, Box<[u8]>)>;

/// A Tokio-based SOCKS5 client.
pub struct Socks5Client {
    stream:      Compat<TcpStream>,
    credentials: CredentialsHolder,
}

impl Socks5Client {
    pub fn new(stream: TcpStream, credentials: CredentialsHolder) -> Self {
        Self {
            stream: stream.compat(),
            credentials,
        }
    }
}

impl Client<TcpStream, Compat<TcpStream>> for Socks5Client {
    fn stream(&mut self) -> &mut Compat<TcpStream> {
        &mut self.stream
    }

    /// Establishes a connection to a target host via the SOCKS5 proxy.
    ///
    /// Supports [AuthenticationMethod::NO_AUTHENTICATION] and
    /// [AuthenticationMethod::USERNAME_PASSWORD].
    ///
    /// # Errors
    ///
    /// Returns `ClientError::UnsupportedAuthMethod` if the server requires
    /// authentication. Other errors can occur if the handshake or
    /// connection request fails.
    async fn connect_to_target(
        mut self,
        target_addr: Address,
        target_port: u16,
    ) -> Result<TcpStream, super::ClientError> {
        let choice = self
            .perform_handshake(
                [
                    AuthenticationMethod::NO_AUTHENTICATION,
                    AuthenticationMethod::USERNAME_PASSWORD,
                ]
                .into(),
            )
            .await?;

        match choice {
            | AuthenticationMethod::NO_AUTHENTICATION => {
                self.send_connect_request(target_addr, target_port).await?;
                Ok(self.stream.into_inner())
            },
            | AuthenticationMethod::USERNAME_PASSWORD => {
                let username = self.credentials.0.clone();
                let password = self.credentials.1.clone();
                username_password_auth_impl(&mut self, username, password).await?;
                self.send_connect_request(target_addr, target_port).await?;
                Ok(self.stream.into_inner())
            },
            | _ => {
                return Err(ClientError::UnsupportedAuthMethod(choice));
            },
        }
    }
}
