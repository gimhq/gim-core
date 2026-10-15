//! `send-image`, `send-file`, `download`.

use std::path::{Path, PathBuf};

use super::messages::resolve_reply;
use super::sent_output;
use crate::error::{CliError, Result};
use crate::output::{DownloadOut, Output};
use crate::profile::Ctx;

pub const DEFAULT_MIME: &str = "application/octet-stream";

/// MIME type from the file extension (case-insensitive).
pub fn guess_mime(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("heic") => "image/heic",
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        Some("mp4") => "video/mp4",
        Some("zip") => "application/zip",
        _ => DEFAULT_MIME,
    }
}

/// Absolute path of a readable regular file: the outbox reads it after
/// this returns, possibly in a later run from another directory.
fn input_file(path: &Path) -> Result<PathBuf> {
    let path = std::path::absolute(path)?;
    if !path.is_file() {
        return Err(CliError::usage(format!(
            "{} is not a readable file",
            path.display()
        )));
    }
    Ok(path)
}

pub async fn send_media(
    ctx: &Ctx,
    chat: &str,
    path: &Path,
    caption: Option<String>,
    reply: Option<&str>,
    image: bool,
) -> Result<Output> {
    let mime = guess_mime(path);
    if image && !mime.starts_with("image/") {
        return Err(CliError::usage(format!(
            "{} is not an image ({mime}); use send-file",
            path.display()
        )));
    }
    let path = input_file(path)?;
    let chat = ctx.resolve_chat(chat)?;
    let reply_to = resolve_reply(ctx, &chat.group_id, reply)?;
    let id = ctx
        .client
        .send_media(&chat.group_id, &path, mime, caption, reply_to)
        .await?;
    sent_output(ctx, &chat.group_id, &id)
}

pub async fn download(ctx: &Ctx, msg: &str, path: &Path) -> Result<Output> {
    let message = ctx.resolve_message(msg)?;
    let path = std::path::absolute(path)?;
    ctx.client
        .fetch_media(&message.group_id, &message.message_id, &path)
        .await?;
    let size = std::fs::metadata(&path)?.len();
    let out = DownloadOut {
        path: path.display().to_string(),
        size,
    };
    let human = format!("{}\t{size}", out.path);
    Ok(Output::new(&out, human))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mime_table() {
        let mime = |p: &str| guess_mime(Path::new(p));
        assert_eq!(mime("a.png"), "image/png");
        assert_eq!(mime("a.JPG"), "image/jpeg");
        assert_eq!(mime("dir/a.jpeg"), "image/jpeg");
        assert_eq!(mime("a.gif"), "image/gif");
        assert_eq!(mime("a.webp"), "image/webp");
        assert_eq!(mime("a.heic"), "image/heic");
        assert_eq!(mime("chart.pdf"), "application/pdf");
        assert_eq!(mime("notes.txt"), "text/plain");
        assert_eq!(mime("clip.mp4"), "video/mp4");
        assert_eq!(mime("logs.zip"), "application/zip");
        assert_eq!(mime("a.bin"), DEFAULT_MIME);
        assert_eq!(mime("README"), DEFAULT_MIME);
    }
}
