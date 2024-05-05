use std::{
    pin::Pin,
    sync::Arc,
    task::{ready, Poll},
};

use anyhow::Error;
use futures::Future;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::ServerConfig;
use uuid::Uuid;

use crate::utils::recorder::StreamRecorder;

use super::Connection;

pub struct DebugConnection<C>
where
    C: Connection,
{
    uuid: Uuid,
    recorder: StreamRecorder<C>,
}

impl<C> DebugConnection<C>
where
    C: Connection,
{
    pub async fn try_new(inner: C) -> std::io::Result<Self> {
        let uuid = uuid::Uuid::new_v4();
        let recorder = StreamRecorder::try_new(inner, uuid).await?;

        Ok(DebugConnection { uuid, recorder })
    }

    pub fn uuid(&self) -> Uuid {
        self.uuid
    }
}

impl<C> Connection for DebugConnection<C>
where
    C: Connection + Send + 'static,
    C::Upgrade: Future<Output = Result<C, Error>> + Send + 'static,
{
    type Upgrade = DebugConnectionUpgrade<C>;

    fn upgrade(self, config: Arc<ServerConfig>) -> Result<Self::Upgrade, Error> {
        let upgrade = self.recorder.into_inner().upgrade(config)?;
        Ok(DebugConnectionUpgrade::new(Box::pin(upgrade), self.uuid))
    }

    fn is_starttls_allowed(&self) -> bool {
        self.recorder.get_ref().is_starttls_allowed()
    }

    fn is_secure(&self) -> bool {
        self.recorder.get_ref().is_secure()
    }

    fn is_authenticated(&self) -> bool {
        self.recorder.get_ref().is_authenticated()
    }
}

impl<C> AsyncRead for DebugConnection<C>
where
    C: Connection,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.recorder).poll_read(cx, buf)
    }
}

impl<C> AsyncWrite for DebugConnection<C>
where
    C: Connection,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        Pin::new(&mut self.recorder).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.recorder).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut self.recorder).poll_shutdown(cx)
    }
}

enum DebugConnectionUpgradeState<C>
where
    C: Connection,
{
    Upgrading(Uuid, Pin<Box<dyn Future<Output = Result<C, Error>> + Send>>),
    ConstructingRecorder(
        Uuid,
        Pin<Box<dyn Future<Output = std::io::Result<StreamRecorder<C>>> + Send>>,
    ),
}

pub struct DebugConnectionUpgrade<C>
where
    C: Connection + Send,
{
    state: DebugConnectionUpgradeState<C>,
}

impl<C> DebugConnectionUpgrade<C>
where
    C: Connection + Send,
{
    pub fn new(
        upgrade: Pin<Box<dyn Future<Output = Result<C, Error>> + Send>>,
        uuid: Uuid,
    ) -> Self {
        let state = DebugConnectionUpgradeState::Upgrading(uuid, upgrade);
        DebugConnectionUpgrade { state }
    }
}

impl<C> Future for DebugConnectionUpgrade<C>
where
    C: Connection + Send + 'static,
{
    type Output = Result<DebugConnection<C>, Error>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        loop {
            self.state = match self.state {
                DebugConnectionUpgradeState::Upgrading(uuid, ref mut upgrade) => {
                    let upgraded = ready!(upgrade.as_mut().poll(cx))?;
                    let recorder_constructor = Box::pin(StreamRecorder::try_new(upgraded, uuid));

                    DebugConnectionUpgradeState::ConstructingRecorder(uuid, recorder_constructor)
                }
                DebugConnectionUpgradeState::ConstructingRecorder(uuid, ref mut constructor) => {
                    let recorder = ready!(constructor.as_mut().poll(cx))?;
                    return Poll::Ready(Ok(DebugConnection { uuid, recorder }));
                }
            }
        }
    }
}
