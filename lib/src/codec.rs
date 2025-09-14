#![allow(async_fn_in_trait)]

use std::fmt::Debug;

use futures::{
    AsyncRead,
    AsyncWrite,
};

pub trait Encoder<E: Debug + From<std::io::Error>> {
    async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<(), E>;
}

pub trait Decoder<E: Debug + From<std::io::Error>>: Sized {
    async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self, E>;
}
