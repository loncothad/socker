use futures::{
    AsyncRead,
    AsyncReadExt,
    AsyncWrite,
    AsyncWriteExt,
};

use super::*;
use crate::codec::{
    Decoder,
    Encoder,
};

#[derive(Debug, Clone)]
pub struct ClientGreeting {
    pub authentication_methods: Box<[AuthenticationMethod]>,
}

impl Encoder<ConversionError> for ClientGreeting {
    async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), ConversionError> {
        writer.write_all(&[VERSION]).await?;

        writer
            .write_all(&[self.authentication_methods.len() as _])
            .await?;

        for method in self.authentication_methods.iter() {
            writer.write_all(&[method.0]).await?;
        }

        Ok(())
    }
}

impl Decoder<ConversionError> for ClientGreeting {
    async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ConversionError> {
        let mut version_buf = [0u8; 1];
        reader.read_exact(&mut version_buf).await?;
        let version = version_buf[0];

        if version != VERSION {
            return Err(ConversionError::InvalidProtocolVersion(version));
        }

        let mut nmethods_buf = [0u8; 1];
        reader.read_exact(&mut nmethods_buf).await?;
        let nmethods = nmethods_buf[0];
        let mut methods = vec![0u8; nmethods as usize];
        reader.read_exact(&mut methods).await?;

        Ok(Self {
            authentication_methods: methods
                .into_iter()
                .map(AuthenticationMethod)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ServerChoice {
    pub chosen_authentication_method: AuthenticationMethod,
}

impl Encoder<ConversionError> for ServerChoice {
    async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), ConversionError> {
        writer.write_all(&[VERSION]).await?;

        writer
            .write_all(&[self.chosen_authentication_method.0])
            .await?;

        Ok(())
    }
}

impl Decoder<ConversionError> for ServerChoice {
    async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ConversionError> {
        let mut buf = [0u8; 2];
        reader.read_exact(&mut buf).await?;
        if buf[0] != VERSION {
            return Err(ConversionError::InvalidProtocolVersion(buf[0]));
        }

        Ok(Self {
            chosen_authentication_method: AuthenticationMethod(buf[1]),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Request {
    pub command: CommandType,
    pub address: Address,
    pub port:    u16,
}

impl Encoder<ConversionError> for Request {
    async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), ConversionError> {
        writer.write_all(&[VERSION]).await?;

        writer.write_all(&[self.command.0]).await?;

        writer.write_all(&[0x00]).await?; // RSV

        self.address.write_to(writer).await?;
        writer.write_all(&self.port.to_be_bytes()).await?;

        Ok(())
    }
}

impl Decoder<ConversionError> for Request {
    async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ConversionError> {
        let mut ver_buf = [0u8; 1];
        reader.read_exact(&mut ver_buf).await?;
        if ver_buf[0] != VERSION {
            return Err(ConversionError::InvalidProtocolVersion(ver_buf[0]));
        }

        let mut cmd_buf = [0u8; 1];
        reader.read_exact(&mut cmd_buf).await?;
        let command = CommandType(cmd_buf[0]);

        // skip RSV byte
        let mut rsv_buf = [0u8; 1];
        reader.read_exact(&mut rsv_buf).await?;

        let address = Address::read_from(reader).await?;

        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        Ok(Request {
            command,
            address,
            port,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Response {
    pub reply:   Reply,
    pub address: Address,
    pub port:    u16,
}

impl Response {
    pub const HOST_UNREACHABLE: Response = Self::new_error(Reply::HOST_UNREACHABLE);
    pub const UNSUPPORTED_COMMAND: Response = Self::new_error(Reply::COMMAND_NOT_SUPPORTED);

    const fn new_error(reply: Reply) -> Self {
        Self {
            reply,
            address: Address::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
            port: 0,
        }
    }
}

impl Encoder<ConversionError> for Response {
    async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), ConversionError> {
        writer.write_all(&[VERSION]).await?;

        writer.write_all(&[self.reply.0]).await?;

        writer.write_all(&[0x00]).await?; // RSV

        self.address.write_to(writer).await?;
        writer.write_all(&self.port.to_be_bytes()).await?;

        Ok(())
    }
}

impl Decoder<ConversionError> for Response {
    async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, ConversionError> {
        let mut version_buf = [0u8; 1];
        reader.read_exact(&mut version_buf).await?;
        let version = version_buf[0];
        if version != VERSION {
            return Err(ConversionError::InvalidProtocolVersion(version));
        }

        let mut reply_buf = [0u8; 1];
        reader.read_exact(&mut reply_buf).await?;
        let reply = Reply(reply_buf[0]);

        let mut rsv_buf = [0u8; 1];
        reader.read_exact(&mut rsv_buf).await?; // RSV

        let address = Address::read_from(reader).await?;

        let mut port_buf = [0u8; 2];
        reader.read_exact(&mut port_buf).await?;
        let port = u16::from_be_bytes(port_buf);

        Ok(Response {
            reply,
            address,
            port,
        })
    }
}

pub mod auth {
    use super::*;

    pub mod username_password {
        use super::*;

        pub const AUTH_VERSION: u8 = 0x01;

        #[derive(Debug, Clone)]
        pub struct ClientAuthenticationRequest {
            pub username: Box<[u8]>,
            pub password: Box<[u8]>,
        }

        impl Encoder<ConversionError> for ClientAuthenticationRequest {
            async fn write_to<W: AsyncWrite + Unpin>(
                &self,
                writer: &mut W,
            ) -> Result<(), ConversionError> {
                writer.write_all(&[AUTH_VERSION]).await?;

                writer.write_all(&[self.username.len() as u8]).await?;
                writer.write_all(&self.username).await?;

                writer.write_all(&[self.password.len() as u8]).await?;
                writer.write_all(&self.password).await?;

                Ok(())
            }
        }

        impl Decoder<ConversionError> for ClientAuthenticationRequest {
            async fn read_from<R: AsyncRead + Unpin>(
                reader: &mut R,
            ) -> Result<Self, ConversionError> {
                let mut ver_buf = [0u8; 1];
                reader.read_exact(&mut ver_buf).await?;
                if ver_buf[0] != AUTH_VERSION {
                    return Err(ConversionError::InvalidProtocolVersion(ver_buf[0]));
                }

                let mut ulen_buf = [0u8; 1];
                reader.read_exact(&mut ulen_buf).await?;
                let ulen = ulen_buf[0];
                let mut username = vec![0u8; ulen as usize];
                reader.read_exact(&mut username).await?;

                let mut plen_buf = [0u8; 1];
                reader.read_exact(&mut plen_buf).await?;
                let plen = plen_buf[0];
                let mut password = vec![0u8; plen as usize];
                reader.read_exact(&mut password).await?;

                Ok(Self {
                    username: username.into_boxed_slice(),
                    password: password.into_boxed_slice(),
                })
            }
        }

        #[derive(Debug, Clone)]
        pub struct ServerResponse {
            pub status: Status,
        }

        impl ServerResponse {
            pub const FAILURE: ServerResponse = ServerResponse {
                status: Status::FAILURE,
            };
            pub const SUCCESS: ServerResponse = ServerResponse {
                status: Status::SUCCESS,
            };
        }

        impl Encoder<ConversionError> for ServerResponse {
            async fn write_to<W: AsyncWrite + Unpin>(
                &self,
                writer: &mut W,
            ) -> Result<(), ConversionError> {
                writer.write_all(&[AUTH_VERSION, self.status.0]).await?;
                Ok(())
            }
        }

        impl Decoder<ConversionError> for ServerResponse {
            async fn read_from<R: AsyncRead + Unpin>(
                reader: &mut R,
            ) -> Result<Self, ConversionError> {
                let mut buf = [0u8; 2];
                reader.read_exact(&mut buf).await?;
                if buf[0] != AUTH_VERSION {
                    return Err(ConversionError::InvalidProtocolVersion(buf[0]));
                }
                Ok(Self {
                    status: Status(buf[1]),
                })
            }
        }
    }
}
