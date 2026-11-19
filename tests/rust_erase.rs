// SPDX-License-Identifier: MIT
use enzimos_installer::erase;
use serde_json::json;
fn guids() -> [String; 4] {
    [
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
        "33333333-3333-4333-8333-333333333333",
        "44444444-4444-4444-8444-444444444444",
    ]
    .map(str::to_owned)
}
#[test]
fn erased_geometry_is_sector_correct_and_readback_requires_exact_owned_guids() {
    for sector in [512, 4096] {
        let bytes = 32 * 1024 * 1024 * 1024;
        let plan = erase::layout(bytes, sector, "/dev/vda", &guids()).unwrap();
        let rows = plan["partitions"].as_array().unwrap();
        assert_eq!(rows[0]["start"].as_u64().unwrap() * sector, 1024 * 1024);
        assert_eq!(
            rows[1]["size"].as_u64().unwrap() * sector,
            4 * 1024 * 1024 * 1024
        );
        let end = (rows[2]["start"].as_u64().unwrap() + rows[2]["size"].as_u64().unwrap()) * sector;
        assert_eq!(end, bytes - 1024 * 1024);
        let mut table = json!({"label":"gpt","device":"/dev/vda","id":plan["label_id"],"sectorsize":sector,"partitions":rows});
        for (i, row) in table["partitions"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            row["node"] = json!(format!("/dev/vda{}", i + 1));
        }
        assert_eq!(erase::verify(&plan, &table).unwrap()["esp"], "/dev/vda2");
        let mut vendor = table.clone();
        vendor["id"] = json!(vendor["id"].as_str().unwrap().to_ascii_uppercase());
        for row in vendor["partitions"].as_array_mut().unwrap() {
            for key in ["uuid", "type"] {
                row[key] = json!(row[key].as_str().unwrap().to_ascii_uppercase());
            }
        }
        assert_eq!(
            erase::verify(&plan, &vendor).unwrap(),
            erase::verify(&plan, &table).unwrap()
        );
        for bad in [
            json!(null),
            json!(true),
            json!("11111111_1111_4111_8111_111111111111"),
            json!("１１１１１１１１-1111-4111-8111-111111111111"),
        ] {
            let mut changed = vendor.clone();
            changed["id"] = bad;
            assert!(erase::verify(&plan, &changed).is_err());
        }
        let mut changed = vendor;
        changed["device"] = json!("/dev/VDA");
        assert!(erase::verify(&plan, &changed).is_err());
        for (key, replacement) in [
            ("uuid", json!(guids()[1])),
            ("size", json!(1)),
            ("name", json!("other")),
            ("type", json!("wrong")),
            ("node", json!("/dev/vda")),
        ] {
            let mut changed = table.clone();
            changed["partitions"][1][key] = replacement;
            assert!(erase::verify(&plan, &changed).is_err(), "{key}");
        }
        let mut changed = table.clone();
        changed["partitions"]
            .as_array_mut()
            .unwrap()
            .push(table["partitions"][0].clone());
        assert!(erase::verify(&plan, &changed).is_err());
        changed = table;
        changed["id"] = json!(guids()[1]);
        assert!(erase::verify(&plan, &changed).is_err());
        let definitions = erase::definitions(&plan).unwrap();
        assert_eq!(definitions.len(), 3);
        assert_eq!(definitions[1].0, "20-enzimos-esp.conf");
        assert!(
            definitions[1]
                .1
                .contains("SizeMinBytes=4294967296\nSizeMaxBytes=4294967296\n")
        );
        assert!(
            definitions
                .iter()
                .all(|(_, body)| body.matches("UUID=").count() == 1)
        );
    }
    for (bytes, sector) in [
        (23 * 1024 * 1024 * 1024, 512),
        (32 * 1024 * 1024 * 1024, 1024),
        (32 * 1024 * 1024 * 1024 + 1, 4096),
    ] {
        assert!(erase::layout(bytes, sector, "/dev/vda", &guids()).is_err());
    }
    let mut duplicate = guids();
    duplicate[3] = duplicate[2].clone();
    assert!(erase::layout(32 * 1024 * 1024 * 1024, 512, "/dev/vda", &duplicate).is_err());
}

fn repart_table(bytes: u64, sector: u64) -> Option<(serde_json::Value, serde_json::Value)> {
    if !std::path::Path::new("/usr/bin/systemd-repart").exists() {
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let image = dir.path().join("disk.img");
    std::fs::File::create(&image)
        .unwrap()
        .set_len(bytes)
        .unwrap();
    let plan = erase::layout(bytes, sector, "/dev/vda", &guids()).unwrap();
    let definitions = dir.path().join("definitions");
    std::fs::create_dir(&definitions).unwrap();
    for (name, body) in erase::definitions(&plan).unwrap() {
        std::fs::write(definitions.join(name), body).unwrap();
    }
    let status = std::process::Command::new("/usr/bin/systemd-repart")
        .args([
            "--empty=force",
            "--dry-run=no",
            "--discard=no",
            "--no-pager",
        ])
        .arg(format!("--definitions={}", definitions.display()))
        .arg(format!("--seed={}", plan["label_id"].as_str().unwrap()))
        .arg(format!("--sector-size={sector}"))
        .arg(&image)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());
    let output = std::process::Command::new("/usr/bin/sfdisk")
        .args(["--json", "--sector-size", &sector.to_string()])
        .arg(&image)
        .output()
        .unwrap();
    let mut table: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // Name the image as the device the plan reviewed; geometry stays as written.
    let image = image.to_str().unwrap().to_owned();
    let mut table = table["partitiontable"].take();
    table["device"] = json!("/dev/vda");
    for row in table["partitions"].as_array_mut().unwrap() {
        let node = row["node"].as_str().unwrap().replace(&image, "/dev/vda");
        row["node"] = json!(node);
    }
    Some((plan, table))
}

/// The real systemd-repart reproduces the reviewed sectors exactly.
#[test]
fn systemd_repart_writes_the_reviewed_geometry() {
    for sector in [512, 4096] {
        let Some((plan, table)) = repart_table(32 * 1024 * 1024 * 1024, sector) else {
            return;
        };
        assert_ne!(
            table["id"].as_str().unwrap().to_ascii_lowercase(),
            plan["label_id"]
        );
        assert!(
            erase::verify(&plan, &table).is_err(),
            "seeded disk GUID is adopted, not assumed"
        );
        let realized = erase::realize(&plan, &table).unwrap();
        let result = erase::verify(&realized, &table).unwrap();
        assert_eq!(result["plan"], realized);
        assert_eq!(result["root"], "/dev/vda3");
        // The realized plan is still exactly the reviewed layout for its GUIDs.
        let guids = [
            realized["label_id"].as_str().unwrap().to_owned(),
            guids()[1].clone(),
            guids()[2].clone(),
            guids()[3].clone(),
        ];
        assert_eq!(
            erase::layout(
                plan["bytes"].as_u64().unwrap(),
                sector,
                plan["disk"].as_str().unwrap(),
                &guids
            )
            .unwrap(),
            realized
        );
    }
}

#[test]
fn a_disk_guid_equal_to_a_partition_uuid_is_refused() {
    let plan = erase::layout(32 * 1024 * 1024 * 1024, 512, "/dev/vda", &guids()).unwrap();
    let table = json!({"id": guids()[2].to_ascii_uppercase()});
    assert!(erase::realize(&plan, &table).is_err());
    assert!(erase::realize(&plan, &json!({"id": "x"})).is_err());
}
