// Copyright (c) 2019-2022 Alibaba Cloud
// Copyright (c) 2019-2022 Ant Group
//
// SPDX-License-Identifier: Apache-2.0
//

use std::os::unix::io::RawFd;

use anyhow::{Context, Result};
use kata_sys_util::spec::get_bundle_path;

use crate::{
    logger,
    shim::{ShimExecutor, ENV_KATA_RUNTIME_BIND_FD},
    Error,
};

impl ShimExecutor {
    pub async fn run(&mut self) -> Result<()> {
        crate::panic_hook::set_panic_hook();
        let sid = self.args.id.clone();
        let bundle_path = get_bundle_path().context("get bundle")?;
        let path = bundle_path.join("log");
        let _logger_guard =
            logger::set_logger(path.to_str().unwrap(), &sid, self.args.debug).context("set logger");

        self.do_run()
            .await
            .map_err(|err| {
                error!(sl!(), "failed run shim {:?}", err);
                err
            })
            .context("run shim")?;

        Ok(())
    }

    async fn do_run(&mut self) -> Result<()> {
        info!(sl!(), "start to run");
        self.args.validate(false).context("validate")?;

        let server_fd = get_server_fd().context("get server fd")?;
        let mut service_manager = service::ServiceManager::new(
            &self.args.id,
            &self.args.publish_binary,
            &self.args.address,
            &self.args.namespace,
            server_fd,
        )
        .await
        .context("new shim server")?;
        service_manager.run().await.context("run")?;

        Ok(())
    }
}

fn get_server_fd() -> Result<RawFd> {
    let env_fd = std::env::var(ENV_KATA_RUNTIME_BIND_FD).map_err(Error::EnvVar)?;
    let fd = env_fd
        .parse::<RawFd>()
        .map_err(|_| Error::ServerFd(env_fd))?;
    Ok(fd)
}
