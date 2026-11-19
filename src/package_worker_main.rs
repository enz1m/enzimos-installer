// SPDX-License-Identifier: MIT
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let result = (|| -> enzimos_platform::Result<()> {
        enzimos_installer::setup::live()?;
        // The graphical installer follows this worker's journal; tool output goes there live.
        enzimos_platform::process::echo_child_output(true);
        enzimos_platform::require(
            args.len() == 2 && args[0] == "serve",
            "fixed installer package service invocation required",
        )?;
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| enzimos_platform::Error("installer service runtime unavailable".into()))?
            .block_on(enzimos_installer::package_service::serve(&args[1]))
    })();
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
