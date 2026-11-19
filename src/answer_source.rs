// SPDX-License-Identifier: MIT
//! Retain the private answer inode and re-read its bytes before installation steps.
use crate::answers::{self, Answers};
use enzimos_platform::{Result, files, mount_identity, require};
use std::{
    fs::File,
    os::{
        fd::{AsFd, AsRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;
fn read(file: &File) -> Result<Zeroizing<Vec<u8>>> {
    crate::private_file::read(file, answers::MAX_FILE, 0)
}
pub struct Source {
    file: File,
    path: PathBuf,
    identity: files::FileIdentity,
    mount: u64,
    bytes: Zeroizing<Vec<u8>>,
    pub(crate) boot_security: crate::boot_security_source::Source,
    pub answers: Answers,
    pub(crate) test_copy: Option<crate::test_copy::Copy>,
}
impl Source {
    /// Overwrite the private answers inode (it holds the account password and
    /// the disk passphrase) and remove it. Only for flows where nothing reopens
    /// it by path afterwards; the inode identity is checked before writing.
    pub(crate) fn retire(&self) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut writer = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.path)?;
        require(
            files::identity(&writer.metadata()?).0 == self.identity.0
                && files::identity(&writer.metadata()?).1 == self.identity.1,
            "answers inode replaced before retirement",
        )?;
        let length = writer.metadata()?.len() as usize;
        writer.write_all(&vec![0u8; length])?;
        writer.sync_all()?;
        drop(writer);
        std::fs::remove_file(&self.path)?;
        Ok(())
    }
    #[allow(
        unsafe_code,
        reason = "Linux syscall ABI (getrlimit, prctl, setrlimit)."
    )]
    pub(crate) fn protect() -> Result<()> {
        crate::setup::live()?;
        let mut descriptors: libc::rlimit = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut descriptors) } == 0
                && descriptors.rlim_max >= 4096,
            "installer descriptor retention limit unavailable",
        )?;
        descriptors.rlim_cur = descriptors.rlim_cur.max(4096);
        require(
            unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &descriptors) } == 0,
            "installer descriptor retention limit setup failed",
        )?;
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        require(
            unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0
                && unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0,
            "installer secret process protection unavailable",
        )?;
        Ok(())
    }
    pub fn open(path: &Path) -> Result<Self> {
        Self::protect()?;
        require(
            path.is_absolute() && path.starts_with("/run/"),
            "private live installer answers required",
        )?;
        let parent = files::directory(path.parent().unwrap(), Some(0))?;
        let file = files::open_relative(
            &parent,
            Path::new(
                path.file_name()
                    .ok_or_else(|| enzimos_platform::Error("answer filename missing".into()))?,
            ),
        )?;
        Self::received(file, path)
    }
    pub(crate) fn received(file: File, path: &Path) -> Result<Self> {
        Self::receive_impl(file, path, None, false)
    }
    pub(crate) fn received_with_test(file: File, path: &Path, test: Option<File>) -> Result<Self> {
        Self::receive_impl(file, path, test, true)
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (fcntl, getrlimit, prctl).")]
    fn receive_impl(file: File, path: &Path, test: Option<File>, worker: bool) -> Result<Self> {
        crate::setup::live()?;
        require(
            unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0,
            "answer handoff requires protected native worker before reading secrets",
        )?;
        let mut core: libc::rlimit = unsafe { std::mem::zeroed() };
        require(
            unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut core) } == 0
                && core.rlim_cur == 0
                && core.rlim_max == 0,
            "answer handoff requires disabled core dumps",
        )?;
        require(
            path.is_absolute()
                && path.starts_with("/run/")
                && path.as_os_str().as_encoded_bytes().len() <= 4096
                && path.components().all(|c| {
                    matches!(
                        c,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                }),
            "private live answer path shape",
        )?;
        let m = file.metadata()?;
        require(
            m.is_file()
                && m.uid() == 0
                && m.gid() == 0
                && m.mode() & 0o7777 == 0o600
                && m.nlink() == 1
                && m.len() <= answers::MAX_FILE as u64,
            "answers must be a private Root-owned regular file",
        )?;
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        require(
            flags >= 0 && flags & libc::O_ACCMODE == libc::O_RDONLY,
            "answer source requires an original read-only description",
        )?;
        let bytes = read(&file)?;
        let answers = Answers::from_values(answers::parse(&bytes)?)?;
        require(
            !worker || answers.test_check == test.is_some(),
            "test mode requires the original caller script descriptor",
        )?;
        let test_copy = if answers.test_check {
            Some(crate::test_copy::Copy::received(test)?)
        } else {
            require(test.is_none(), "unexpected test copy descriptor")?;
            None
        };
        let boot_security = crate::boot_security_source::Source::observe(answers.encrypted)?;
        let mount = mount_identity::id(file.as_fd(), true)?;
        let source = Self {
            file,
            path: path.into(),
            identity: files::identity(&m),
            mount,
            bytes,
            boot_security,
            answers,
            test_copy,
        };
        source.recheck()?;
        Ok(source)
    }
    pub(crate) fn descriptor(&self) -> &File {
        &self.file
    }
    pub(crate) fn binding(&self) -> Result<serde_json::Value> {
        self.recheck()?;
        let path = self
            .path
            .to_str()
            .ok_or_else(|| enzimos_platform::Error("answer source path encoding".into()))?;
        Ok(serde_json::json!({"path":path,"mount":self.mount,"inode":self.identity}))
    }
    #[allow(unsafe_code, reason = "Linux syscall ABI (prctl).")]
    pub fn recheck(&self) -> Result<()> {
        crate::setup::live()?;
        self.boot_security.recheck()?;
        if let Some(copy) = &self.test_copy {
            copy.recheck()?;
        }
        require(
            unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } == 0,
            "installer secret process protection changed",
        )?;
        let parent = files::directory(self.path.parent().unwrap(), Some(0))?;
        let named = files::open_relative(&parent, Path::new(self.path.file_name().unwrap()))?;
        require(
            files::identity(&named.metadata()?) == self.identity
                && files::identity(&self.file.metadata()?) == self.identity
                && mount_identity::id(named.as_fd(), true)? == self.mount
                && mount_identity::id(self.file.as_fd(), true)? == self.mount
                && read(&self.file)?.as_slice() == self.bytes.as_slice(),
            "installer answer source changed",
        )
    }
}
