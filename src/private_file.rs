// SPDX-License-Identifier: MIT
//! Stable pread with both returned bytes and intermediate secret buffers zeroed.
use enzimos_platform::{Result, files, require};
use std::{
    fs::File,
    os::unix::fs::{FileExt, MetadataExt},
};
use zeroize::Zeroizing;
pub(crate) fn validate_inode(inode: &serde_json::Value, mode: u32, limit: u64) -> Result<()> {
    let a = inode
        .as_array()
        .ok_or_else(|| enzimos_platform::Error("private inode binding type".into()))?;
    require(
        a.len() == 11
            && a.iter().all(|n| n.is_i64() || n.is_u64())
            && a[0].as_u64().is_some_and(|n| n > 0)
            && a[1].as_u64().is_some_and(|n| n > 0)
            && a[2].as_u64().is_some_and(|n| n <= limit)
            && a[7].as_u64() == Some(u64::from(libc::S_IFREG | mode))
            && a[8] == 0
            && a[9] == 0
            && a[10] == 1
            && [4, 6].iter().all(|i| {
                a[*i]
                    .as_i64()
                    .is_some_and(|n| (0..1_000_000_000).contains(&n))
            }),
        "private file bound, type, clock, protection or identity differs",
    )
}
pub(crate) fn read(file: &File, limit: usize, owner: u32) -> Result<Zeroizing<Vec<u8>>> {
    require(limit > 0 && limit <= 1024 * 1024, "private file read bound")?;
    let before = file.metadata()?;
    require(
        before.is_file()
            && before.uid() == owner
            && before.mode() & 0o022 == 0
            && before.nlink() == 1
            && before.len() <= limit as u64,
        "private file read authority, type or size",
    )?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(before.len() as usize));
    let mut chunk = Zeroizing::new([0u8; 8192]);
    loop {
        let n = file.read_at(&mut *chunk, bytes.len() as u64)?;
        if n == 0 {
            break;
        }
        require(
            bytes.len() + n <= limit,
            "private file grew beyond read bound",
        )?;
        bytes.extend_from_slice(&chunk[..n]);
    }
    require(
        bytes.len() as u64 == before.len()
            && files::identity(&file.metadata()?) == files::identity(&before),
        "private file changed during read",
    )?;
    Ok(bytes)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Seek, SeekFrom};
    #[test]
    #[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
    fn private_pread_preserves_shared_offset_and_refuses_hardlinks_and_growth_bounds() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("secret");
        std::fs::write(&path, b"private bytes").unwrap();
        let mut file = File::open(&path).unwrap();
        file.seek(SeekFrom::Start(5)).unwrap();
        let owner = unsafe { libc::geteuid() };
        assert_eq!(&*read(&file, 64, owner).unwrap(), b"private bytes");
        assert_eq!(file.stream_position().unwrap(), 5);
        assert!(read(&file, 4, owner).is_err());
        std::fs::hard_link(path, temp.path().join("alias")).unwrap();
        assert!(read(&file, 64, owner).is_err());
    }
}
