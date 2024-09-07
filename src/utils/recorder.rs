use std::{
    pin::Pin,
    task::{ready, Poll},
};

use bytes::BufMut;
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncRead, AsyncWrite, ReadBuf},
};
use uuid::Uuid;

const BUFFER_SIZE: usize = 1024;

pub struct StreamRecorder<S> {
    inner_stream: S,
    read_done: bool,
    write_done: bool,
    input_recording: File,
    output_recording: File,
    input_buffer: Box<[u8]>,
    input_buffer_read: usize,
    input_buffer_written: usize,
    output_buffer: Box<[u8]>,
    output_bytes_written: usize,
    output_bytes_recorded: usize,
    inner_stream_needs_flush: bool,
    input_recording_needs_flush: bool,
    output_recording_needs_flush: bool,
    input_recording_done: bool,
    output_recording_done: bool,
}

impl<S> StreamRecorder<S> {
    pub async fn try_new(wrapped_stream: S, uuid: Uuid) -> std::io::Result<Self> {
        let input_recording = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&format!("log/{uuid}.in.xml"))
            .await?;
        let output_recording = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&format!("log/{uuid}.out.xml"))
            .await?;

        Ok(Self {
            inner_stream: wrapped_stream,
            read_done: false,
            write_done: false,
            input_recording,
            output_recording,
            input_buffer: vec![0; BUFFER_SIZE].into_boxed_slice(),
            input_buffer_read: 0,
            input_buffer_written: 0,
            output_buffer: vec![0; BUFFER_SIZE].into_boxed_slice(),
            output_bytes_written: 0,
            output_bytes_recorded: 0,
            inner_stream_needs_flush: false,
            input_recording_needs_flush: false,
            output_recording_needs_flush: false,
            input_recording_done: false,
            output_recording_done: false,
        })
    }

    pub fn get_ref(&self) -> &S {
        &self.inner_stream
    }

    pub fn into_inner(self) -> S {
        self.inner_stream
    }
}

impl<S> AsyncRead for StreamRecorder<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let me = &mut *self;

        loop {
            if me.input_buffer_written == me.input_buffer_read && !me.read_done {
                me.input_buffer_read = 0;
                me.input_buffer_written = 0;
                let mut input_buffer = ReadBuf::new(me.input_buffer.as_mut());

                match Pin::new(&mut me.inner_stream).poll_read(cx, &mut input_buffer) {
                    Poll::Ready(Ok(_)) => {
                        let filled_len = input_buffer.filled().len();
                        me.read_done = filled_len == me.input_buffer_read;
                        me.input_buffer_read = filled_len;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if me.input_buffer_written < me.input_buffer_read {
                let num_bytes_to_write = std::cmp::min(
                    buf.remaining(),
                    me.input_buffer_read - me.input_buffer_written,
                );

                match Pin::new(&mut me.input_recording).poll_write(
                    cx,
                    &me.input_buffer
                        [me.input_buffer_written..(me.input_buffer_written + num_bytes_to_write)],
                ) {
                    Poll::Ready(Ok(num_bytes_written)) => {
                        buf.put_slice(
                            &me.input_buffer[me.input_buffer_written
                                ..(me.input_buffer_written + num_bytes_written)],
                        );
                        me.input_buffer_written += num_bytes_written;
                        me.input_recording_needs_flush = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if me.input_buffer_written == me.input_buffer_read && me.read_done {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

impl<S> AsyncWrite for StreamRecorder<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let me = &mut *self;

        if me.output_bytes_written == me.output_bytes_recorded {
            me.output_bytes_written = 0;
            me.output_bytes_recorded = 0;

            let num_bytes_to_write = std::cmp::min(buf.len(), me.output_buffer.len());
            let num_bytes_written =
                ready!(Pin::new(&mut me.inner_stream).poll_write(cx, &buf[..num_bytes_to_write]))?;

            me.output_buffer
                .as_mut()
                .put_slice(&buf[..num_bytes_written]);
            me.output_bytes_written += num_bytes_written;
            me.inner_stream_needs_flush = true;
        }

        debug_assert!(me.output_bytes_recorded < me.output_bytes_written);

        let num_bytes_written = ready!(
            Pin::new(&mut me.output_recording).poll_write(cx, &buf[..me.output_bytes_written])
        )?;
        me.output_bytes_recorded += num_bytes_written;
        me.output_recording_needs_flush = true;
        Poll::Ready(Ok(num_bytes_written))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let me = &mut *self;

        if me.output_bytes_recorded < me.output_bytes_written {
            let num_bytes_written = ready!(Pin::new(&mut me.output_recording)
                .poll_write(cx, &me.output_buffer[me.output_bytes_recorded..]))?;
            me.output_bytes_recorded += num_bytes_written;
            cx.waker().wake_by_ref();
            Poll::Pending
        } else {
            if me.inner_stream_needs_flush {
                ready!(Pin::new(&mut me.inner_stream).poll_flush(cx))?;
                me.inner_stream_needs_flush = false;
            }

            if me.input_recording_needs_flush {
                ready!(Pin::new(&mut me.input_recording).poll_flush(cx))?;
                me.input_recording_needs_flush = false;
            }

            if me.output_recording_needs_flush {
                ready!(Pin::new(&mut me.output_recording).poll_flush(cx))?;
                me.output_recording_needs_flush = false;
            }

            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let mut me = &mut *self;

        if me.output_bytes_recorded < me.output_bytes_written
            || me.inner_stream_needs_flush
            || me.input_recording_needs_flush
            || me.output_recording_needs_flush
        {
            ready!(Pin::new(&mut me).poll_flush(cx))?;
        }

        if !me.write_done {
            ready!(Pin::new(&mut me.inner_stream).poll_shutdown(cx))?;
            me.write_done = true;
        }

        if !me.input_recording_done {
            ready!(Pin::new(&mut me.output_recording).poll_shutdown(cx))?;
            me.input_recording_done = true;
        }

        if !me.output_recording_done {
            ready!(Pin::new(&mut me.output_recording).poll_shutdown(cx))?;
            me.output_recording_done = true;
        }

        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use uuid::Uuid;

    use super::{StreamRecorder, BUFFER_SIZE};

    #[tokio::test]
    async fn read_bytes_are_recorded() {
        let original_data = (0..1_000_000)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let data = original_data.clone();

        let uuid = Uuid::new_v4();

        let (rx, mut tx) = duplex(1000);
        let mut recorder = StreamRecorder::try_new(rx, uuid).await.unwrap();

        let write = tokio::spawn(async move {
            tx.write_all(&data).await.unwrap();
        });

        let read = tokio::spawn(async move {
            let mut buffer = [0u8; 1001];
            loop {
                let n = recorder.read(&mut buffer).await.unwrap();

                if n == 0 {
                    break;
                }
            }

            recorder.flush().await.unwrap();
        });

        write.await.unwrap();
        read.await.unwrap();

        let recording = format!("log/{uuid}.in.xml");
        let recorded_data = std::fs::read(&recording).unwrap();
        std::fs::remove_file(&recording).unwrap();
        std::fs::remove_file(format!("log/{uuid}.out.xml")).unwrap();

        assert_eq!(recorded_data.len(), original_data.len());
        assert!(recorded_data
            .iter()
            .zip(original_data.iter())
            .all(|(a, b)| a == b));
    }

    async fn written_bytes_are_recorded(
        data_len: usize,
        duplex_buf_size: usize,
        read_buf_size: usize,
    ) {
        let original_data = (0..data_len)
            .map(|_| rand::random::<u8>())
            .collect::<Vec<_>>();

        let data = original_data.clone();

        let uuid = Uuid::new_v4();

        let (mut rx, tx) = duplex(duplex_buf_size);
        let mut recorder = StreamRecorder::try_new(tx, uuid).await.unwrap();

        let write = tokio::spawn(async move {
            recorder.write_all(&data).await.unwrap();
            recorder.flush().await.unwrap();
        });

        let read = tokio::spawn(async move {
            let mut buffer = vec![0u8; read_buf_size];
            loop {
                let n = rx.read(&mut buffer).await.unwrap();

                if n == 0 {
                    break;
                }
            }
        });

        write.await.unwrap();
        read.await.unwrap();

        let recording = format!("log/{uuid}.out.xml");
        let recorded_data = std::fs::read(&recording).unwrap();
        std::fs::remove_file(&recording).unwrap();
        std::fs::remove_file(format!("log/{uuid}.in.xml")).unwrap();

        assert_eq!(recorded_data.len(), original_data.len());
        assert!(recorded_data
            .iter()
            .zip(original_data.iter())
            .all(|(a, b)| a == b));
    }

    #[tokio::test]
    async fn write_with_duplex_buf_bigger_than_internal_buf() {
        written_bytes_are_recorded(1_000_000, BUFFER_SIZE * 2, 1_001).await;
    }

    #[tokio::test]
    async fn write_with_duplex_buf_smaller_than_internal_buf() {
        written_bytes_are_recorded(1_000_000, BUFFER_SIZE / 2, 1_001).await;
    }
}
