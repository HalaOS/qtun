use futures::{io::copy, AsyncRead, AsyncWrite, AsyncWriteExt};

pub(crate) async fn tunnel_copy<R, W>(debug_info: String, reader: R, mut writer: W)
where
    R: AsyncRead,
    W: AsyncWrite + Unpin,
{
    log::info!("{:?}", debug_info);

    match copy(reader, &mut writer).await {
        Ok(bytes) => {
            log::info!("{:?}, EOF with transferred {}", debug_info, bytes);
        }
        Err(err) => {
            log::error!("{:?}, broken with error, {}", debug_info, err);
        }
    }

    close_writer(debug_info, &mut writer).await;
}

async fn close_writer<W>(debug_info: String, writer: &mut W)
where
    W: AsyncWrite + Unpin + ?Sized,
{
    match writer.close().await {
        Ok(_) => {
            log::info!("{:?}, try close write stream", debug_info);
        }
        Err(err) => {
            log::error!(
                "{:?}, try close write stream, with error, {}",
                debug_info,
                err
            );
        }
    };
}
