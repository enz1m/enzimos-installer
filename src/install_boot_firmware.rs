// SPDX-License-Identifier: MIT
//! A separately journaled EFI entry publication; prior boot entries must remain byte-identical.
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{collections::BTreeMap, path::Path};
const EFI: &str = "/sys/firmware/efi/efivars";
const GUID: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";
const LOADER: &str = "\\EFI\\enzimos\\refind_x64.efi";
fn entry_name(name: &str) -> bool {
    name.len() == 45
        && name.starts_with("Boot")
        && name.ends_with(GUID)
        && name.as_bytes()[8] == b'-'
        && name[4..8].bytes().all(|b| b.is_ascii_hexdigit())
}
pub(crate) fn capture() -> Result<Value> {
    snapshot()
}
fn snapshot() -> Result<Value> {
    crate::setup::live()?;
    let directory = files::directory(Path::new(EFI), Some(0))?;
    let mut entries = BTreeMap::new();
    for (index, entry) in files::directory_names(&directory, 4096)?
        .into_iter()
        .enumerate()
    {
        require(index < 4096, "firmware variable count bound")?;
        let name = entry
            .into_string()
            .map_err(|_| Error("firmware variable name encoding".into()))?;
        if !entry_name(&name) {
            continue;
        }
        require(entries.len() < 256, "firmware boot entry count bound")?;
        let file = files::open_relative(&directory, Path::new(&name))?;
        let bytes = files::read_file(&file, 65536, Some(0), false)?;
        entries.insert(name, json::sha256(&bytes));
    }
    let order = files::read_optional(
        &Path::new(EFI).join(format!("BootOrder-{GUID}")),
        516,
        Some(0),
        false,
    )?;
    let order = match order {
        None => Vec::new(),
        Some(b) => {
            require(
                b.len() >= 4 && b.len() % 2 == 0,
                "firmware BootOrder framing",
            )?;
            b[4..]
                .chunks_exact(2)
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect()
        }
    };
    Ok(value!({"entries":entries,"order":order}))
}
pub(crate) fn verify(body: &Value) -> Result<()> {
    validate(body)?;
    let name = body["entry"]
        .as_str()
        .ok_or_else(|| Error("unfinished firmware publication is not replayed".into()))?;
    let bytes = files::read(&Path::new(EFI).join(name), 65536, Some(0), false)?;
    require(
        json::sha256(&bytes) == body["entry_sha256"] && parse(&bytes)? == body["partition"],
        "new EFI entry bytes or physical partition changed",
    )?;
    let current = snapshot()?;
    let mut expected = body["before"]["entries"].clone();
    expected
        .as_object_mut()
        .unwrap()
        .insert(name.into(), body["entry_sha256"].clone());
    let id = u16::from_str_radix(&name[4..8], 16)
        .map_err(|_| Error("EFI entry number encoding".into()))?;
    let mut order = vec![value!(id)];
    order.extend(body["before"]["order"].as_array().unwrap().iter().cloned());
    require(
        current["entries"] == expected && current["order"] == value!(order),
        "prior firmware entries or order changed outside original publication",
    )
}
pub(crate) fn published(mut body: Value) -> Result<Value> {
    validate(&body)?;
    require(
        body["entry"].is_null() && body["entry_sha256"].is_null(),
        "firmware entry publication cannot be replayed",
    )?;
    let current = snapshot()?;
    let before = body["before"]["entries"].as_object().unwrap();
    let added = current["entries"]
        .as_object()
        .unwrap()
        .iter()
        .filter(|(name, _)| !before.contains_key(*name))
        .collect::<Vec<_>>();
    require(
        added.len() == 1,
        "EFI publication must create exactly one new entry",
    )?;
    body["entry"] = value!(added[0].0);
    body["entry_sha256"] = added[0].1.clone();
    verify(&body)?;
    Ok(body)
}
fn description(bytes: &[u8]) -> Result<String> {
    require(bytes.len() >= 12, "firmware load option framing")?;
    let mut units = Vec::new();
    for pair in bytes[10..].chunks_exact(2).take(129) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            return String::from_utf16(&units)
                .map_err(|_| Error("firmware description encoding".into()));
        }
        units.push(unit);
    }
    Err(Error("firmware description terminator or bound".into()))
}
pub(crate) fn parse(bytes: &[u8]) -> Result<Value> {
    let label = description(bytes)?;
    require(
        label == "enzimOS" && u32::from_le_bytes(bytes[4..8].try_into().unwrap()) == 1,
        "new boot entry label or active flags",
    )?;
    let path_len = u16::from_le_bytes(bytes[8..10].try_into().unwrap()) as usize;
    let start = 10 + (label.encode_utf16().count() + 1) * 2;
    require(
        start + path_len == bytes.len(),
        "new EFI entry cannot contain unreviewed optional data",
    )?;
    let path = &bytes[start..];
    require(
        path.len() >= 50 && path[..4] == [4, 1, 42, 0] && path[40..42] == [2, 2],
        "new EFI hard drive node must bind GPT GUID",
    )?;
    let number = u32::from_le_bytes(path[4..8].try_into().unwrap());
    let offset = u64::from_le_bytes(path[8..16].try_into().unwrap());
    let size = u64::from_le_bytes(path[16..24].try_into().unwrap());
    let b = &path[24..40];
    let uuid = format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes(b[0..4].try_into().unwrap()),
        u16::from_le_bytes(b[4..6].try_into().unwrap()),
        u16::from_le_bytes(b[6..8].try_into().unwrap()),
        b[8],
        b[9],
        b[10..]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    require(path[42..44] == [4, 4], "new EFI file path node type")?;
    let file_len = u16::from_le_bytes(path[44..46].try_into().unwrap()) as usize;
    require(
        file_len >= 6
            && file_len.is_multiple_of(2)
            && 42 + file_len + 4 == path.len()
            && path[path.len() - 4..] == [127, 255, 4, 0],
        "new EFI file path framing",
    )?;
    let units = path[46..42 + file_len]
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes([p[0], p[1]]))
        .collect::<Vec<_>>();
    require(units.last() == Some(&0), "new EFI file path terminator")?;
    let loader = String::from_utf16(&units[..units.len() - 1])
        .map_err(|_| Error("EFI loader encoding".into()))?;
    require(
        loader == LOADER && number > 0 && size > 0,
        "new EFI entry loader or partition bound",
    )?;
    Ok(
        value!({"partition":number,"offset":offset,"size":size,"uuid":uuid,"loader":loader,"label":label}),
    )
}
pub(crate) fn validate(body: &Value) -> Result<()> {
    json::fields(body, "before entry entry_sha256 partition")?;
    json::fields(&body["before"], "entries order")?;
    let map = body["before"]["entries"]
        .as_object()
        .ok_or_else(|| Error("EFI before entries type".into()))?;
    require(
        map.len() <= 256 && map.keys().all(|s| entry_name(s)),
        "EFI before closed entry names",
    )?;
    for sha in map.values() {
        enzimos_policy::identity::sha(
            sha.as_str()
                .ok_or_else(|| Error("EFI entry digest type".into()))?,
        )?;
    }
    let order = body["before"]["order"]
        .as_array()
        .ok_or_else(|| Error("EFI boot order type".into()))?;
    require(
        order.len() <= 256 && order.iter().all(|n| n.as_u64().is_some_and(|n| n <= 65535)),
        "EFI before order bound",
    )?;
    json::fields(
        &body["partition"],
        "partition offset size uuid loader label",
    )?;
    require(
        body["partition"]["partition"]
            .as_u64()
            .is_some_and(|n| n > 0 && n <= u64::from(u32::MAX))
            && body["partition"]["offset"].is_u64()
            && body["partition"]["size"].as_u64().is_some_and(|n| n > 0)
            && body["partition"]["loader"] == LOADER
            && body["partition"]["label"] == "enzimOS",
        "EFI partition binding scalar types",
    )?;
    enzimos_policy::identity::uuid(
        body["partition"]["uuid"]
            .as_str()
            .ok_or_else(|| Error("EFI GPT UUID type".into()))?,
    )?;
    require(
        body["entry"].is_null() == body["entry_sha256"].is_null(),
        "EFI publication digest must accompany exact new entry",
    )?;
    if !body["entry"].is_null() {
        let name = body["entry"]
            .as_str()
            .ok_or_else(|| Error("EFI entry name type".into()))?;
        require(
            entry_name(name) && !map.contains_key(name),
            "EFI entry must be fresh",
        )?;
        enzimos_policy::identity::sha(
            body["entry_sha256"]
                .as_str()
                .ok_or_else(|| Error("EFI entry digest absent".into()))?,
        )?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn option() -> Vec<u8> {
        let mut path = vec![4, 1, 42, 0];
        path.extend(1u32.to_le_bytes());
        path.extend(2048u64.to_le_bytes());
        path.extend(1048576u64.to_le_bytes());
        path.extend([0x11u8; 16]);
        path.extend([2, 2]);
        let filename = LOADER
            .encode_utf16()
            .chain(Some(0))
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        path.extend([4, 4]);
        path.extend(((filename.len() + 4) as u16).to_le_bytes());
        path.extend(filename);
        path.extend([127, 255, 4, 0]);
        let mut body = 7u32.to_le_bytes().to_vec();
        body.extend(1u32.to_le_bytes());
        body.extend((path.len() as u16).to_le_bytes());
        body.extend(
            "enzimOS"
                .encode_utf16()
                .chain(Some(0))
                .flat_map(u16::to_le_bytes),
        );
        body.extend(path);
        body
    }
    #[test]
    fn exact_firmware_load_option_binds_gpt_partition_and_loader_without_optional_arguments() {
        let body = option();
        let parsed = parse(&body).unwrap();
        assert_eq!(
            parsed,
            value!({"partition":1,"offset":2048,"size":1048576,"uuid":"11111111-1111-1111-1111-111111111111","loader":LOADER,"label":"enzimOS"})
        );
        for length in 0..body.len() {
            assert!(parse(&body[..length]).is_err(), "{length}");
        }
        let mut extra = body.clone();
        extra.extend(b"init=/bin/sh");
        assert!(parse(&extra).is_err());
        let mut inactive = body.clone();
        inactive[4] = 0;
        assert!(parse(&inactive).is_err());
        let start = 10 + ("enzimOS".len() + 1) * 2;
        let mut mbr = body.clone();
        mbr[start + 40] = 1;
        assert!(parse(&mbr).is_err());
        let mut alternate = body;
        alternate[start + 46] = b'X';
        assert!(parse(&alternate).is_err());
    }
    #[test]
    fn publication_receipt_refuses_reusing_a_prior_firmware_entry_or_half_a_result() {
        let entry = format!("Boot0001-{GUID}");
        let good = value!({"before":{"entries":{},"order":[2,3]},"entry":entry,"entry_sha256":"a".repeat(64),"partition":parse(&option()).unwrap()});
        validate(&good).unwrap();
        let mut reused = good.clone();
        reused["before"]["entries"][&entry] = value!("a".repeat(64));
        assert!(validate(&reused).is_err());
        let mut partial = good.clone();
        partial["entry_sha256"] = Value::Null;
        assert!(validate(&partial).is_err());
        let mut scalar = good;
        scalar["before"]["order"][0] = value!("2");
        assert!(validate(&scalar).is_err());
    }
}
