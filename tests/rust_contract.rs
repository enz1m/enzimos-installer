// SPDX-License-Identifier: MIT
use enzimos_installer::{contract, network, partition};
use enzimos_platform::json;
use serde_json::{Value, json as value};

fn fixture(mode: &str) -> (Value, Value) {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures");
    let read = |suffix: &str| {
        json::decode(
            &std::fs::read(base.join(format!("{mode}-{suffix}.json"))).unwrap(),
            2 * 1024 * 1024,
        )
        .unwrap()
    };
    (read("inventory"), read("plan"))
}
#[test]
fn existing_uefi_bios_contracts_keep_digests_and_refuse_execution() {
    for mode in ["uefi", "bios"] {
        let (inventory, plan) = fixture(mode);
        assert_eq!(
            json::fingerprint(&inventory).unwrap(),
            plan["inventory_sha256"]
        );
        let result = contract::validate(&inventory, &plan).unwrap();
        assert_eq!(result["contract_valid"], true);
        assert_eq!(result["execution_available"], false);
        assert_eq!(result["release_qualified"], false);
    }
}
#[test]
fn stale_or_weakened_plan_refuses() {
    let (inventory, plan) = fixture("uefi");
    for (pointer, replacement) in [
        ("/loader", value!("grub")),
        ("/secure_boot", value!("disabled")),
        ("/schema_version", value!(true)),
        ("/encryption/explicit_opt_out", value!(0)),
        ("/root/os_rollback_reverts_home", value!(true)),
        ("/swap/snapshots", value!(true)),
        ("/allocations/0/free_region", value!("windows")),
        ("/allocations/0/size_bytes", value!(true)),
        ("/allocations/0/size_bytes", value!(-1)),
        ("/allocations/0/start_bytes", value!(u64::MAX)),
        ("/allocations/1/start_bytes", value!(68719476736u64)),
        ("/allocations/0/role", value!("root")),
    ] {
        let mut changed = plan.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            contract::validate(&inventory, &changed).is_err(),
            "accepted {pointer}"
        );
    }
    let mut changed = plan;
    changed["apply"] = value!(true);
    assert!(contract::validate(&inventory, &changed).is_err());
}
#[test]
fn dishonest_inventory_refuses_even_with_a_fresh_digest() {
    let (inventory, plan) = fixture("uefi");
    for (pointer, replacement) in [
        ("/synthetic", value!(false)),
        ("/disk_size_bytes", value!(true)),
        ("/windows_firmware", value!("bios")),
        ("/regions", value!([])),
        ("/regions/1/start_bytes", value!(2147483648u64)),
        ("/regions/1/owner", value!("windows")),
        ("/regions/1/id", value!("windows")),
        ("/device_id", value!("../../dev/sda")),
    ] {
        let mut changed = inventory.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        let mut plan = plan.clone();
        plan["inventory_sha256"] = value!(json::fingerprint(&changed).unwrap());
        assert!(
            contract::validate(&changed, &plan).is_err(),
            "accepted {pointer}"
        );
    }
}
#[test]
fn wireless_profile_escapes_text_and_refuses_injection() {
    let ap = value!({"ssid":"Coffee: House\\Wi-Fi","security":"WPA2","supported":true});
    let text = network::wifi_profile(&ap, "space secret", "fixture").unwrap();
    assert!(text.contains("ssid=Coffee:\\sHouse\\\\Wi-Fi"));
    assert!(text.contains("psk=space\\ssecret"));
    let numeric_ssid = value!({"ssid":"16;17;","security":"--","supported":true});
    let profile = network::wifi_profile(&numeric_ssid, "", "fixture").unwrap();
    assert!(profile.lines().any(|line| line == r"ssid=16\\;17\\;"));
    assert!(network::wifi_profile(&numeric_ssid, "unexpected", "fixture").is_err());
    for password in ["short", "abcdefgh\n[connection]", "abcdefgh\0injection"] {
        assert!(network::wifi_profile(&ap, password, "fixture").is_err());
    }
    assert_eq!(
        network::rows(r"*:Coffee\: House\\Wi-Fi:02\:00\:00\:00\:00\:01:82:WPA2:wlan0")[0],
        vec![
            "*",
            "Coffee: House\\Wi-Fi",
            "02:00:00:00:00:01",
            "82",
            "WPA2",
            "wlan0"
        ]
    );
}
#[test]
fn free_space_geometry_preserves_existing_extents_and_refuses_overlap() {
    let gib = 1024u64.pow(3);
    for sector in [512, 4096] {
        let unit = 1024 * 1024 / sector;
        let mut table = value!({"firstlba":34,"lastlba":100*gib/sector-34,"sectorsize":sector,"partitions":[{"start":unit,"size":20*gib/sector},{"start":40*gib/sector,"size":10*gib/sector}]});
        for (start, size) in partition::free_regions(&table).unwrap() {
            assert_eq!(start % unit, 0);
            assert_eq!(size % unit, 0);
            for old in table["partitions"].as_array().unwrap() {
                let a = old["start"].as_u64().unwrap();
                let b = old["size"].as_u64().unwrap();
                assert!(start + size <= a || start >= a + b);
            }
        }
        table["partitions"][1]["start"] = value!(unit + 1);
        assert!(partition::free_regions(&table).is_err());
        table["lastlba"] = value!(u64::MAX);
        assert!(partition::free_regions(&table).is_err());
    }
}
