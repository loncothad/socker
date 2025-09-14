pub mod messages;

use std::fmt::Debug;

use caret::caret_int;
use futures::{
    AsyncReadExt,
    AsyncWriteExt,
};

use crate::codec::{
    Decoder,
    Encoder,
};

pub const VERSION: u8 = 0x05;

#[derive(Debug)]
pub enum ConversionError {
    InvalidProtocolVersion(u8),
    MalformedMessage,
    IoError(std::io::Error),
}

impl From<std::io::Error> for ConversionError {
    fn from(value: std::io::Error) -> Self {
        Self::IoError(value)
    }
}

caret_int! {
    pub struct AuthenticationMethod(u8) {
        NO_AUTHENTICATION = 0x00,
        GSSAPI = 0x01,
        USERNAME_PASSWORD = 0x02,
        IANA_CHALLENGE_HANDSHAKE = 0x03,
        IANA_CHALLENGE_RESPONSE = 0x05,
        IANA_SECURE_SOCKETS_LAYER = 0x06,
        IANA_NDS = 0x07,
        IANA_MULTI_AUTHENTICATION_FRAMEWORK = 0x08,
        IANA_JSON_PARAMETER_BLOCK = 0x09,
        NO_ACCEPTABLE_METHODS = 0xFF,
    }
}

impl AuthenticationMethod {
    #[inline]
    pub fn is_iana_unassigned(&self) -> bool {
        matches!(self.0, 0x04 | 0x0A ..= 0x7F)
    }

    #[inline]
    pub fn is_reserved_for_private_use(&self) -> bool {
        matches!(self.0, 0x80 ..= 0xFE)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Status(pub u8);

impl Status {
    pub const FAILURE: Status = Status(1);
    pub const SUCCESS: Status = Status(0);
}

impl Status {
    pub fn is_success(&self) -> bool {
        matches!(self.0, 0x00)
    }

    pub fn is_failure(&self) -> bool {
        matches!(self.0, 0x01 ..= 0xFF)
    }
}

impl PartialEq for Status {
    fn eq(&self, other: &Self) -> bool {
        self.is_success() == other.is_success()
    }
}

impl Eq for Status {}

impl From<u8> for Status {
    fn from(value: u8) -> Self {
        Status(value)
    }
}

impl Into<u8> for Status {
    fn into(self) -> u8 {
        self.0
    }
}

caret_int! {
    pub struct AddressType(u8) {
        IP_V4 = 0x01,
        DOMAIN_NAME = 0x03,
        IP_V6 = 0x04,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Address {
    Ipv4(std::net::Ipv4Addr),
    Domain(Box<[u8]>),
    Ipv6(std::net::Ipv6Addr),
}

impl From<std::net::Ipv4Addr> for Address {
    fn from(value: std::net::Ipv4Addr) -> Self {
        Address::Ipv4(value)
    }
}

impl From<std::net::Ipv6Addr> for Address {
    fn from(value: std::net::Ipv6Addr) -> Self {
        Address::Ipv6(value)
    }
}

impl From<String> for Address {
    fn from(value: String) -> Self {
        Address::Domain(value.into_bytes().into_boxed_slice())
    }
}

impl From<&str> for Address {
    fn from(value: &str) -> Self {
        Address::Domain(
            value
                .as_bytes()
                .iter()
                .cloned()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        )
    }
}

impl From<Box<[u8]>> for Address {
    fn from(value: Box<[u8]>) -> Self {
        Address::Domain(value)
    }
}

impl From<&[u8]> for Address {
    fn from(value: &[u8]) -> Self {
        Address::Domain(value.iter().cloned().collect::<Vec<_>>().into_boxed_slice())
    }
}

impl Encoder<ConversionError> for Address {
    async fn write_to<W: futures::AsyncWrite + Unpin>(
        &self,
        writer: &mut W,
    ) -> Result<(), ConversionError> {
        use Address::*;

        match self {
            | Ipv4(addr) => {
                writer.write_all(&[AddressType::IP_V4.0]).await?;
                writer.write_all(&addr.octets()).await?;
            },
            | Domain(domain) => {
                writer.write_all(&[AddressType::DOMAIN_NAME.0]).await?;
                writer
                    .write_all(&(domain.len() as u8).to_be_bytes())
                    .await?;
                writer.write_all(domain).await?;
            },
            | Ipv6(addr) => {
                writer.write_all(&[AddressType::IP_V6.0]).await?;
                writer.write_all(&addr.octets()).await?;
            },
        }
        Ok(())
    }
}

impl Decoder<ConversionError> for Address {
    async fn read_from<R: futures::AsyncRead + Unpin>(
        reader: &mut R,
    ) -> Result<Self, ConversionError> {
        let mut address_type_buf = [0u8; 1];
        reader.read_exact(&mut address_type_buf).await?;
        let address_type = address_type_buf[0];
        match address_type.into() {
            | AddressType::IP_V4 => {
                let mut octets = [0u8; 4];
                reader.read_exact(&mut octets).await?;
                Ok(Address::Ipv4(octets.into()))
            },
            | AddressType::DOMAIN_NAME => {
                let mut len_buf = [0u8; 1];
                reader.read_exact(&mut len_buf).await?;
                let len = len_buf[0];
                let mut domain = vec![0u8; len as usize];
                reader.read_exact(&mut domain).await?;
                Ok(Address::Domain(domain.into_boxed_slice()))
            },
            | AddressType::IP_V6 => {
                let mut octets = [0u8; 16];
                reader.read_exact(&mut octets).await?;
                Ok(Address::Ipv6(octets.into()))
            },
            | _ => Err(ConversionError::MalformedMessage),
        }
    }
}

caret_int! {
    pub struct CommandType(u8) {
        CONNECT = 0x01,
        BIND = 0x02,
        UDP_ASSOCIATE = 0x03,
    }
}

caret_int! {
    pub struct Reply(u8) {
        SUCCESS = 0x00,
        GENERAL_FAILURE = 0x01,
        CONNECTION_NOT_ALLOWED_BY_RULESET = 0x02,
        NETWORK_UNREACHABLE = 0x03,
        HOST_UNREACHABLE = 0x04,
        CONNECTION_REFUSED = 0x05,
        TTL_EXPIRED = 0x06,
        COMMAND_NOT_SUPPORTED = 0x07,
        ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
    }
}

impl Reply {
    pub fn is_success(&self) -> bool {
        self == &Reply::SUCCESS
    }

    pub fn is_unassigned(&self) -> bool {
        matches!(self.0, 0x09 ..= 0xFF)
    }
}
