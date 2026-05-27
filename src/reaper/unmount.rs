//! `Unmount` trait so the sweep loop can be tested without real syscalls.
//! Linux production impl uses `libc::umount2(MNT_DETACH)`.

use std::io;
use std::path::Path;

pub trait Unmount: Send + Sync {
    /// Lazily detach the filesystem at `path`. On success returns Ok(()).
    fn umount(&self, path: &Path) -> io::Result<()>;
}

#[cfg(target_os = "linux")]
pub struct LibcUnmount;

#[cfg(target_os = "linux")]
impl Unmount for LibcUnmount {
    fn umount(&self, path: &Path) -> io::Result<()> {
        use std::ffi::CString;
        let cstr = CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        // SAFETY: cstr.as_ptr() is a valid C string for the duration of the call.
        let rc = unsafe { libc::umount2(cstr.as_ptr(), libc::MNT_DETACH) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub struct LibcUnmount;

#[cfg(not(target_os = "linux"))]
impl Unmount for LibcUnmount {
    fn umount(&self, _path: &Path) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "umount2 is Linux-only",
        ))
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use std::sync::Mutex;

    pub struct MockUnmount {
        pub calls: Mutex<Vec<std::path::PathBuf>>,
        pub fail_for: Vec<std::path::PathBuf>,
    }

    impl MockUnmount {
        pub fn new() -> Self {
            Self {
                calls: Mutex::new(vec![]),
                fail_for: vec![],
            }
        }
        pub fn fail_on(mut self, path: impl Into<std::path::PathBuf>) -> Self {
            self.fail_for.push(path.into());
            self
        }
    }

    impl Unmount for MockUnmount {
        fn umount(&self, path: &Path) -> io::Result<()> {
            self.calls.lock().unwrap().push(path.to_path_buf());
            if self.fail_for.iter().any(|p| p == path) {
                Err(io::Error::from_raw_os_error(libc::EBUSY))
            } else {
                Ok(())
            }
        }
    }
}
