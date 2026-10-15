//! `register`, `whoami`, `users search`.

use std::path::Path;

use gim_base::StateReader;

use crate::error::{CliError, Result};
use crate::output::{Output, RegisterOut, UserOut, UsersOut, WhoamiOut};
use crate::profile::{Ctx, Profile};

pub async fn register(
    dir: &Path,
    server: Option<&str>,
    handle: &str,
    display_name: &str,
) -> Result<Output> {
    let mut profile = Profile::create(dir)?;
    let server = profile
        .server(server)
        .ok_or_else(|| CliError::usage("register requires --server (or GIM_SERVER)"))?;
    let client = profile.client(&server)?;
    if client.restore_session().await? {
        return Err(CliError::usage("profile is already registered"));
    }
    let handle = handle.strip_prefix('@').unwrap_or(handle);
    let session = client.register(handle, display_name).await?;
    profile.config.server = Some(server.clone());
    profile.config.save(&profile.dir)?;
    let out = RegisterOut {
        user_id: session.device.user_id.to_string(),
        device_id: session.device.device_id.to_string(),
        handle: handle.to_string(),
        server,
    };
    let human = format!(
        "registered @{} as {} (device {})",
        out.handle, out.user_id, out.device_id
    );
    Ok(Output::new(&out, human))
}

pub fn whoami(ctx: &Ctx) -> Result<Output> {
    let device = &ctx.session.device;
    let me = ctx.store().user(&device.user_id)?;
    let out = WhoamiOut {
        user_id: device.user_id.to_string(),
        device_id: device.device_id.to_string(),
        handle: me.as_ref().map(|u| u.handle.clone()),
        display_name: me.map(|u| u.display_name),
        server: ctx.server.clone(),
    };
    let human = format!(
        "user_id: {}\ndevice_id: {}\nhandle: {}\ndisplay_name: {}\nserver: {}",
        out.user_id,
        out.device_id,
        out.handle.as_deref().unwrap_or("-"),
        out.display_name.as_deref().unwrap_or("-"),
        out.server
    );
    Ok(Output::new(&out, human))
}

/// Exact handle lookup: the SDK has no substring search.
pub async fn search_users(ctx: &Ctx, query: &str) -> Result<Output> {
    let query = query.strip_prefix('@').unwrap_or(query);
    let users: Vec<UserOut> = ctx
        .client
        .find_user(query)
        .await?
        .iter()
        .map(UserOut::from)
        .collect();
    let human = users
        .iter()
        .map(|u| format!("@{}\t{}\t{}", u.handle, u.display_name, u.user_id))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(Output::new(&UsersOut { users }, human))
}
