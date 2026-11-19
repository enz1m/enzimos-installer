// SPDX-License-Identifier: MIT
//! One installation package attempt; a PID exit alone cannot complete its receipt.
use enzimos_platform::{Error, Result, json, require};
pub use enzimos_system_backend::native_worker_contract::{
    INSTALLER_EXECUTABLE as EXECUTABLE, INSTALLER_RUNTIME_SECONDS as RUNTIME_SECONDS,
    INSTALLER_STOP_SECONDS as STOP_SECONDS,
};
use serde_json::{Value, json as value};
pub const CALLER: &str = "/usr/lib/enzimos-installer/enzimos-installer-native";
pub const ARCH: &str = "initial-arch-install";
pub const OFFLINE: &str = "initial-offline-install";
pub const SYSTEM: &str = "initial-system-install";
pub const BOOT: &str = "initial-bootable-install";
pub fn configured(operation: &str) -> bool {
    matches!(operation, SYSTEM | BOOT)
}
pub fn operation(value: &str) -> Result<()> {
    require(
        matches!(value, ARCH | OFFLINE | SYSTEM | BOOT),
        "installation package operation outside closed registry",
    )
}
pub fn id(value: &str) -> Result<()> {
    require(
        value.len() == 32
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "installation package attempt identifier",
    )
}
pub fn unit(value: &str) -> Result<String> {
    id(value)?;
    Ok(format!("enzimos-install-package-{value}.service"))
}
pub fn arguments(value: &str) -> Result<Vec<String>> {
    id(value)?;
    Ok(vec![EXECUTABLE.into(), "serve".into(), value.into()])
}
pub fn request(body: &Value) -> Result<()> {
    let system = body["operation"].as_str().is_some_and(configured);
    let boot = body["operation"] == BOOT;
    json::fields(
        body,
        if boot {
            "schema id boot_id operation target media_manifest_sha256 selected target_mount target_inode caller configuration boot"
        } else if system {
            "schema id boot_id operation target media_manifest_sha256 selected target_mount target_inode caller configuration"
        } else {
            "schema id boot_id operation target media_manifest_sha256 selected target_mount target_inode caller"
        },
    )?;
    require(
        body["schema"]
            == if boot {
                if body["boot"].get("test_copy").is_some() {
                    4
                } else {
                    3
                }
            } else if system {
                2
            } else {
                1
            }
            && body["operation"]
                .as_str()
                .is_some_and(|role| operation(role).is_ok())
            && body["target"] == "/mnt/enzimos",
        "installation package job role",
    )?;
    if system {
        configuration(&body["configuration"])?;
    }
    if boot {
        json::fields(
            &body["boot"],
            if body["schema"] == 4 {
                "disk security test_copy"
            } else {
                "disk security"
            },
        )?;
        if body["schema"] == 4 {
            crate::test_copy::validate(&body["boot"]["test_copy"])?;
        }
        crate::install_boot_disk::validate(&body["boot"]["disk"])?;
        crate::boot_security_source::validate(&body["boot"]["security"])?;
        require(
            body["boot"]["security"]["firmware"]["enabled"] != true
                || !body["configuration"]["luks_uuid"].is_null(),
            "owner signing authority cannot be installed on a cleartext root",
        )?;
    }
    id(body["id"]
        .as_str()
        .ok_or_else(|| Error("package attempt missing".into()))?)?;
    enzimos_policy::identity::uuid(
        body["boot_id"]
            .as_str()
            .ok_or_else(|| Error("package boot missing".into()))?,
    )?;
    let hash = body["media_manifest_sha256"]
        .as_str()
        .ok_or_else(|| Error("package media binding missing".into()))?;
    require(
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "package media binding digest",
    )?;
    let inode = body["target_inode"]
        .as_array()
        .ok_or_else(|| Error("package target inode binding missing".into()))?;
    require(
        body["target_mount"].as_u64().is_some_and(|id| id > 0)
            && inode.len() == 5
            && inode[0].as_u64().is_some_and(|n| n > 0)
            && inode[1].as_u64().is_some_and(|n| n > 0)
            && inode[2].as_u64() == Some(0)
            && inode[3].as_u64() == Some(0)
            && inode[4].as_u64().is_some_and(|mode| {
                mode <= u64::from(u32::MAX)
                    && mode as u32 & libc::S_IFMT == libc::S_IFDIR
                    && mode & 0o022 == 0
            }),
        "package target descriptor binding",
    )?;
    let selected = body["selected"]
        .as_array()
        .ok_or_else(|| Error("package selection missing".into()))?;
    require(
        !selected.is_empty() && selected.len() <= 1024,
        "package selection bound",
    )?;
    let rows = selected
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| Error("package filename type".into()))
        })
        .collect::<Result<Vec<_>>>()?;
    let bytes = format!("{}\n", rows.join("\n"));
    require(
        crate::media_manifest::package_list(bytes.as_bytes())?.len() == selected.len(),
        "package selection ambiguity",
    )?;
    json::fields(&body["caller"], "pid start_ticks executable_sha256")?;
    require(
        body["caller"]["pid"]
            .as_u64()
            .is_some_and(|p| p > 1 && p < i32::MAX as u64)
            && body["caller"]["start_ticks"]
                .as_u64()
                .is_some_and(|p| p > 0),
        "package caller identity",
    )?;
    let image = body["caller"]["executable_sha256"]
        .as_str()
        .ok_or_else(|| Error("package caller image digest missing".into()))?;
    require(
        image.len() == 64
            && image
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "package caller image digest",
    )
}
pub fn configuration(body: &Value) -> Result<()> {
    json::fields(body, "filesystem_uuid esp_uuid luks_uuid answers")?;
    enzimos_policy::identity::uuid(
        body["filesystem_uuid"]
            .as_str()
            .ok_or_else(|| Error("configuration root UUID missing".into()))?,
    )?;
    enzimos_policy::recovery_records::fat_uuid(
        body["esp_uuid"]
            .as_str()
            .ok_or_else(|| Error("configuration ESP UUID missing".into()))?,
    )?;
    if !body["luks_uuid"].is_null() {
        enzimos_policy::identity::uuid(
            body["luks_uuid"]
                .as_str()
                .ok_or_else(|| Error("configuration LUKS UUID type".into()))?,
        )?;
    }
    let source = &body["answers"];
    json::fields(source, "path mount inode")?;
    let path = source["path"]
        .as_str()
        .ok_or_else(|| Error("answer source pathname type".into()))?;
    require(
        !path.chars().any(char::is_control),
        "answer source pathname contains control characters",
    )?;
    let path = std::path::Path::new(path);
    require(
        path.is_absolute()
            && path.starts_with("/run/")
            && path.as_os_str().as_encoded_bytes().len() <= 4096
            && path.components().all(|p| {
                matches!(
                    p,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            && source["mount"].as_u64().is_some_and(|n| n > 0),
        "answer source path or unique mount binding",
    )?;
    let inode = source["inode"]
        .as_array()
        .ok_or_else(|| Error("answer source inode binding type".into()))?;
    require(
        inode.len() == 11
            && inode.iter().all(|v| v.is_i64() || v.is_u64())
            && inode[0].as_u64().is_some_and(|n| n > 0)
            && inode[1].as_u64().is_some_and(|n| n > 0)
            && inode[2]
                .as_u64()
                .is_some_and(|n| n > 0 && n <= crate::answers::MAX_FILE as u64)
            && inode[7].as_u64() == Some(u64::from(libc::S_IFREG | 0o600))
            && inode[8] == 0
            && inode[9] == 0
            && inode[10] == 1,
        "answer source protected regular-file identity",
    )
}
pub fn validate(body: &Value) -> Result<()> {
    json::fields(body, "schema request phase owner exit_code group_empty")?;
    require(body["schema"] == 1, "package journal schema")?;
    request(&body["request"])?;
    let phase = body["phase"]
        .as_str()
        .ok_or_else(|| Error("package journal phase missing".into()))?;
    require(
        matches!(
            phase,
            "starting" | "handoff" | "running" | "stopping" | "complete"
        ),
        "package journal phase",
    )?;
    if phase == "starting" {
        require(
            body["owner"].is_null() && body["exit_code"].is_null() && body["group_empty"].is_null(),
            "package starting journal cannot claim worker ownership",
        )?;
    } else {
        let owner = &body["owner"];
        json::fields(owner, "pid start_ticks invocation executable_sha256 unit")?;
        require(
            owner["pid"]
                .as_u64()
                .is_some_and(|p| p > 1 && p < i32::MAX as u64)
                && owner["start_ticks"].as_u64().is_some_and(|p| p > 0)
                && owner["unit"] == unit(body["request"]["id"].as_str().unwrap())?,
            "package journal worker identity",
        )?;
        for key in ["invocation", "executable_sha256"] {
            let text = owner[key]
                .as_str()
                .ok_or_else(|| Error("worker identity encoding".into()))?;
            require(
                text.len() == if key == "invocation" { 32 } else { 64 }
                    && text
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && (key != "invocation" || text.bytes().any(|b| b != b'0')),
                "worker identity digest or invocation",
            )?;
        }
        require(
            if matches!(phase, "stopping" | "complete") {
                body["exit_code"].as_u64() == Some(0)
            } else {
                body["exit_code"].is_null()
            },
            "package journal result ordering",
        )?;
        require(
            if phase == "complete" {
                body["group_empty"] == true
            } else {
                body["group_empty"].is_null()
            },
            "package completion requires exact cgroup emptiness",
        )?;
    }
    Ok(())
}
pub fn transition(before: Option<&Value>, after: &Value) -> Result<()> {
    validate(after)?;
    if let Some(before) = before {
        validate(before)?;
        require(
            before["request"] == after["request"]
                && (before["owner"].is_null() || before["owner"] == after["owner"]),
            "package journal request or measured owner changed",
        )?;
        let expected = match before["phase"].as_str().unwrap() {
            "starting" => "handoff",
            "handoff" => "running",
            "running" => "stopping",
            "stopping" => "complete",
            _ => return Err(Error("completed package attempt cannot replay".into())),
        };
        require(
            after["phase"] == expected,
            "package journal phase cannot skip or repeat",
        )
    } else {
        require(
            after["phase"] == "starting",
            "package attempt begins with durable intent",
        )
    }
}
pub fn initial(request_body: Value) -> Result<Value> {
    request(&request_body)?;
    Ok(
        value!({"schema":1,"request":request_body,"phase":"starting","owner":null,"exit_code":null,"group_empty":null}),
    )
}
