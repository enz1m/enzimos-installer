// SPDX-License-Identifier: MIT
use enzimos_installer::{boot_menu, contract, network, partition, setup, unmount};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::io::Read;
use std::path::{Path, PathBuf};

fn absolute(s: &str) -> Result<PathBuf> {
    let p = Path::new(s);
    Ok(if p.is_absolute() {
        p.to_owned()
    } else {
        std::env::current_dir()?.join(p)
    })
}
fn load(s: &str) -> Result<Value> {
    json::decode(
        &files::read(&absolute(s)?, 2 * 1024 * 1024, None, false)?,
        2 * 1024 * 1024,
    )
}
fn execute(args: &[String]) -> Result<Value> {
    match args.first().map(String::as_str) {
        Some("prepare-answer-mount-area") if args.len()==1 => {
            enzimos_installer::answer_volume::prepare_area()
        },
        Some("prepare-storage-mount-area") if args.len()==1 => {
            enzimos_installer::answer_volume::prepare_storage_area()
        },
        Some("prepare-target-mount-area") if args.len()==1 => {
            enzimos_installer::answer_volume::prepare_target_area()
        },
        Some("inspect-answer-volume") if args.len()==2 => {
            let label=match args[1].as_str() {
                "answers"=>enzimos_policy::installer_volume_device::Label::Answers,
                "testcheck"=>enzimos_policy::installer_volume_device::Label::Testcheck,
                _=>return Err(Error("fixed answer volume label required".into())),
            };
            enzimos_installer::answer_volume::inspect(label)
        },
        Some("install-console") if args.len()==1 => enzimos_installer::console::install(false),
        Some("install-serial-console") if args.len()==1 => enzimos_installer::console::install(true),
        Some("install-fresh-from-stdin") if args.len()==1 => {
            let source=enzimos_installer::answer_transport::stdin()?;
            enzimos_installer::console::finish_fresh(&source)
        },
        Some("install-from-answer-volume") if args.len()==1 => enzimos_installer::answer_volume::install_fresh(),
        Some("prepare-from-answer-volume") if args.len()==1 => enzimos_installer::answer_volume::prepare(),
        Some("install-and-finish") if args.len()==2 => {
            let source=enzimos_installer::answer_source::Source::open(Path::new(&args[1]))?;
            enzimos_installer::install_coordinator::install_and_finish(&source)
        },
        Some("install-from-stdin") if args.len()==1 => {
            let source=enzimos_installer::answer_transport::stdin()?;
            enzimos_installer::install_coordinator::install_and_finish(&source)
        },
        Some("install-ui-from-stdin") if args.len()==1 => {
            enzimos_installer::install_ui::stdin()?;
            Ok(Value::Null)
        },
        Some("prepare-from-stdin") if args.len()==1 => {
            let source=enzimos_installer::answer_transport::stdin()?;
            enzimos_installer::install_coordinator::prepare_bootable(&source)
        },
        Some("prepare-bootable-installation") if args.len()==2 => {
            let source=enzimos_installer::answer_source::Source::open(Path::new(&args[1]))?;
            enzimos_installer::install_coordinator::prepare_bootable(&source)
        },
        Some("install-bootable-system") if args.len()==2 => {
            let source=enzimos_installer::answer_source::Source::open(Path::new(&args[1]))?;
            let media=enzimos_installer::media_packages::Admitted::open(source.answers.gpu)?;
            enzimos_installer::target_storage::with_storage(&source,|target| {
                target.mount_environment()?;
                let journal=tokio::runtime::Builder::new_current_thread().enable_all().build()
                    .map_err(|_|Error("installer boot client runtime unavailable".into()))?
                    .block_on(enzimos_installer::package_client::launch_bootable(target,&media))?;
                Ok(value!({"schema":1,"operation":"install-bootable-system","package_journal":journal,
                    "boot_configured":true,"installed_qualification":false,"installer_runtime":"rust"}))
            })
        },
        Some("install-configured-system") if args.len()==2 => {
            let source=enzimos_installer::answer_source::Source::open(Path::new(&args[1]))?;
            let media=enzimos_installer::media_packages::Admitted::open(source.answers.gpu)?;
            enzimos_installer::target_storage::with_storage(&source,|target| {
                target.mount_environment()?;
                let journal=tokio::runtime::Builder::new_current_thread().enable_all().build()
                    .map_err(|_| Error("installer system client runtime unavailable".into()))?
                    .block_on(enzimos_installer::package_client::launch_system(target,&media))?;
                Ok(value!({"schema":1,"operation":"install-configured-system","package_journal":journal,
                    "boot_configured":false,"installed_qualification":false,"installer_runtime":"rust"}))
            })
        },
        Some("install-offline-packages") if args.len()==2 => {
            let source=enzimos_installer::answer_source::Source::open(Path::new(&args[1]))?;
            let media=enzimos_installer::media_packages::Admitted::open(source.answers.gpu)?;
            enzimos_installer::target_storage::with_storage(&source,|target| {
                target.mount_environment()?;
                let journal=tokio::runtime::Builder::new_current_thread().enable_all().build()
                    .map_err(|_| Error("installer package client runtime unavailable".into()))?
                    .block_on(enzimos_installer::package_client::launch_offline(target,&media))?;
                Ok(value!({"schema":1,"operation":"install-offline-packages","package_journal":journal,
                    "boot_configured":false,"installed_qualification":false,"installer_runtime":"rust"}))
            })
        },
        Some("install-arch-base") if args.len()==2 => {
            let source=enzimos_installer::answer_source::Source::open(Path::new(&args[1]))?;
            let media=enzimos_installer::media_packages::Admitted::open(source.answers.gpu)?;
            enzimos_installer::target_storage::with_storage(&source,|target| {
                target.mount_environment()?;
                let journal=tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| Error("installer package client runtime unavailable".into()))?.block_on(enzimos_installer::package_client::launch(target,&media))?;
                Ok(value!({"schema":1,"operation":"install-arch-base","package_journal":journal,"boot_configured":false,"installed_qualification":false,"installer_runtime":"rust"}))
            })
        },
        Some("preflight-install-media") if args.len()==2 => {
            let source=enzimos_installer::answer_source::Source::open(Path::new(&args[1]))?;
            let media=enzimos_installer::media_packages::Admitted::open(source.answers.gpu)?;
            source.recheck()?;media.recheck()?;
            Ok(media.receipt)
        },
        Some("erase") if args.len()==2 => {
            let source=enzimos_installer::answer_source::Source::open(Path::new(&args[1]))?;
            enzimos_installer::erase::apply(&source)
        },
        Some("format-new-allocation") if args.len()==2 => {
            let source=enzimos_installer::answer_source::Source::open(Path::new(&args[1]))?;
            enzimos_installer::format::apply(&source)
        },
        Some("prepare-root-filesystem") if args.len()==2 => {
            let source=enzimos_installer::answer_source::Source::open(Path::new(&args[1]))?;
            enzimos_installer::root_prepare::prepare(&source)
        },
        Some("prepare-subvolumes") if args.len()==2 => {
            let source=enzimos_installer::answer_source::Source::open(Path::new(&args[1]))?;
            enzimos_installer::subvolume_prepare::prepare(&source)
        },
        Some("validate-answers") if args.len() == 1 => {
            let mut body = zeroize::Zeroizing::new(Vec::with_capacity(enzimos_installer::answers::MAX_FILE + 1));
            std::io::stdin().take((enzimos_installer::answers::MAX_FILE + 1) as u64).read_to_end(&mut body)?;
            Ok(enzimos_installer::answers::Answers::from_values(enzimos_installer::answers::parse(&body)?)?.review())
        },
        Some("validate") if args.len() == 5 => {
            let pairs = args[1..].chunks_exact(2).map(|p| (p[0].as_str(),p[1].as_str())).collect::<std::collections::BTreeMap<_,_>>();
            require(pairs.len() == 2 && pairs.contains_key("--inventory") && pairs.contains_key("--plan"), "validate requires --inventory FILE --plan FILE")?;
            contract::validate(&load(pairs["--inventory"] )?, &load(pairs["--plan"] )?)
        },
        Some("network") if args.len() == 1 => {
            setup::live()?;
            let mut input = Vec::new(); std::io::stdin().take(8193).read_to_end(&mut input)?;
            network::perform(&json::decode(&input, 8192)?)
        },
        Some("export-network") if args.len() == 1 => {
            setup::live()?;
            network::export_connected(Path::new("/mnt/enzimos"))?; Ok(Value::Null)
        },
        Some("storage-minimum") if args.len() == 1 =>
            Ok(value!(enzimos_installer::install_capacity::graphical_minimum()?)),
        Some("partition") if args.len() == 3 && args[1] == "inspect" =>
            partition::inspect_with_minimum(&args[2], enzimos_installer::install_capacity::graphical_minimum()?),
        Some("unmount") if args.len() == 1 => { unmount::finish()?; Ok(Value::Null) },
        Some("disk-idle") if args.len()==2 => {setup::disk_idle(&args[1])?;Ok(Value::Null)},
        Some("enable-multilib") if args.len()==1 => {setup::enable_multilib()?;Ok(Value::Null)},
        Some("secure-preflight") if args.len()==2 => {setup::live()?;require(matches!(args[1].as_str(),"yes"|"no"),"encryption choice required")?;println!("{}",if enzimos_policy::secure_boot::installer_preflight(args[1]=="yes")? {"1"} else {"0"});Ok(Value::Null)},
        Some("install-owner-credentials") if args.len()==1 => {setup::live()?;enzimos_policy::secure_boot::install_owner_credentials(Path::new("/mnt/enzimos"))?;Ok(Value::Null)},
        Some("layout-field") if args.len()==2 => {let mut body=Vec::new();std::io::stdin().take(4097).read_to_end(&mut body)?;let value=json::decode(&body,4096)?;println!("{}",setup::layout_field(&value,&args[1])?);Ok(Value::Null)},
        Some("boot-menu") if args.len() == 1 || (args.len() == 2 && args[1] == "--restore-pending") => { boot_menu::render(Path::new("/boot"), args.len() == 2)?; Ok(Value::Null) },
        _ => Err(Error("usage: enzimos-installer erase PRIVATE_ANSWERS_FILE | format-new-allocation PRIVATE_ANSWERS_FILE | validate --inventory FILE --plan FILE | network | export-network | partition inspect DISK | unmount | disk-idle DISK | enable-multilib | secure-preflight yes|no | install-owner-credentials | layout-field esp|root | boot-menu [--restore-pending]".into())),
    }
}
fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args == ["--help"] || args == ["-h"] {
        println!(
            "enzimos-installer: erase PRIVATE_ANSWERS_FILE; format-new-allocation PRIVATE_ANSWERS_FILE; validate --inventory FILE --plan FILE; network; export-network; partition inspect DISK; partition apply DISK --id DIGEST; unmount; disk-idle DISK; enable-multilib; secure-preflight yes|no; install-owner-credentials; layout-field esp|root; boot-menu [--restore-pending]"
        );
        println!(
            "Native private areas: prepare-answer-mount-area; prepare-storage-mount-area; prepare-target-mount-area (explicit one-shot private binds; no root or run propagation change)"
        );
        println!(
            "Native storage preparation: prepare-root-filesystem PRIVATE_ANSWERS_FILE; prepare-subvolumes PRIVATE_ANSWERS_FILE"
        );
        println!(
            "Offline source admission: preflight-install-media PRIVATE_ANSWERS_FILE (required before native erase)"
        );
        println!(
            "Native coordinated preparation: prepare-bootable-installation PRIVATE_ANSWERS_FILE (reviewed erase or UEFI alongside through boot, requested desktop/offline apps and teardown; guest qualification remains pending)"
        );
        println!(
            "Native finish: install-and-finish PRIVATE_ANSWERS_FILE; install-from-stdin; prepare-from-stdin (private tmpfs answer transport; prepare leaves finish to UI; finish only after normal teardown, no automatic retry)"
        );
        println!(
            "Native live frontends: install-console; install-serial-console; install-fresh-from-stdin; install-from-answer-volume"
        );
        println!(
            "Native unattended preparation: prepare-from-answer-volume (one ENZIMOS_ANSWERS volume; owned read-only mount and normal teardown; caller owns finish)"
        );
        println!(
            "Native initial package body: install-arch-base PRIVATE_ANSWERS_FILE (ready new allocation only; boot configuration remains separate)"
        );
        println!(
            "Native combined package body: install-offline-packages PRIVATE_ANSWERS_FILE (ready new allocation only; system and boot configuration remain separate)"
        );
        return;
    }
    match execute(&args) {
        Ok(result) => {
            if !result.is_null() {
                println!("{}", serde_json::to_string_pretty(&result).unwrap());
            }
        }
        Err(error) => {
            if args.len() == 1 && args[0] == "install-ui-from-stdin" {
                eprintln!(
                    "Installation failed: {}",
                    error.to_string().chars().take(500).collect::<String>()
                );
                std::process::exit(1);
            }
            // The graphical network/partition helpers consume stdout JSON even
            // on refusal. Keep their original wire and exit status separate
            // from the native coordinator's diagnostic stderr contract.
            let graphical = (args.len() == 1 && args[0] == "network")
                || (args.len() == 3 && args[0] == "partition" && args[1] == "inspect");
            if graphical {
                println!("{}", value!({"error":error.to_string()}));
                std::process::exit(1);
            }
            eprintln!(
                "{}",
                value!({"contract_valid":false,"execution_available":false,"error":error.to_string()})
            );
            std::process::exit(2);
        }
    }
}
