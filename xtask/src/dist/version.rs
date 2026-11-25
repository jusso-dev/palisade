//! Version stamping: the workspace SemVer, as the four-part numeric version
//! Windows and Windows Installer use, and as the product version string with
//! the git commit.

use std::fmt;

/// A parsed `MAJOR.MINOR.PATCH[-PRE][+BUILD]` version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
    /// The pre-release part without the `-`, such as `alpha.1`.
    pub pre: Option<String>,
    /// The build metadata without the `+`.
    pub build: Option<String>,
}

impl Version {
    /// Parses a SemVer version. Each numeric part must fit in 16 bits,
    /// because the Windows version resource stores four 16-bit parts.
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = |why: &str| format!("version `{text}`: {why}");
        let (rest, build) = match text.split_once('+') {
            Some((rest, build)) => (rest, Some(build)),
            None => (text, None),
        };
        let (core, pre) = match rest.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (rest, None),
        };
        let parts: Vec<&str> = core.split('.').collect();
        let [major, minor, patch] = parts.as_slice() else {
            return Err(bad("expected MAJOR.MINOR.PATCH"));
        };
        let number = |part: &str| -> Result<u16, String> {
            let valid = !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part == "0" || !part.starts_with('0'));
            if !valid {
                return Err(bad("each part must be a number without leading zeros"));
            }
            part.parse()
                .map_err(|_| bad("each part must be at most 65535"))
        };
        let identifiers = |s: &str, what: &str| -> Result<String, String> {
            let ok = !s.is_empty()
                && s.split('.').all(|id| {
                    !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                });
            if ok {
                Ok(s.to_owned())
            } else {
                Err(bad(&format!("invalid {what}")))
            }
        };
        Ok(Self {
            major: number(major)?,
            minor: number(minor)?,
            patch: number(patch)?,
            pre: pre.map(|p| identifiers(p, "pre-release")).transpose()?,
            build: build
                .map(|b| identifiers(b, "build metadata"))
                .transpose()?,
        })
    }

    /// The four-part file version: `MAJOR.MINOR.PATCH.0`.
    pub const fn quad(&self) -> [u16; 4] {
        [self.major, self.minor, self.patch, 0]
    }

    /// The Windows Installer `ProductVersion`, `MAJOR.MINOR.PATCH`. The
    /// installer allows at most 255 for the first two parts. A pre-release
    /// part cannot be expressed, so `0.2.0-rc.1` and `0.2.0` share it.
    pub fn msi(&self) -> Result<String, String> {
        if self.major > 255 || self.minor > 255 {
            return Err(format!(
                "version {self}: Windows Installer allows at most 255 for MAJOR and MINOR"
            ));
        }
        Ok(format!("{}.{}.{}", self.major, self.minor, self.patch))
    }

    /// The product version string: the SemVer with the commit as build
    /// metadata (`0.1.0+g1a2b3c4d5e6f`), unless the version already has
    /// build metadata.
    pub fn product_string(&self, commit: Option<&str>) -> String {
        match (&self.build, commit) {
            (None, Some(commit)) => format!("{self}+g{commit}"),
            _ => self.to_string(),
        }
    }

    /// `MAJOR.MINOR.PATCH.0`, the file version string.
    pub fn file_string(&self) -> String {
        let [a, b, c, d] = self.quad();
        format!("{a}.{b}.{c}.{d}")
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(pre) = &self.pre {
            write!(f, "-{pre}")?;
        }
        if let Some(build) = &self.build {
            write!(f, "+{build}")?;
        }
        Ok(())
    }
}

/// `true` for a short commit hash as `git rev-parse --short` prints it.
pub fn is_commit(text: &str) -> bool {
    (7..=40).contains(&text.len()) && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release_and_pre_release_versions() {
        let v = Version::parse("0.1.0").unwrap();
        assert_eq!(v.quad(), [0, 1, 0, 0]);
        assert_eq!(v.msi().unwrap(), "0.1.0");
        assert_eq!(v.file_string(), "0.1.0.0");
        assert_eq!(
            v.product_string(Some("1a2b3c4d5e6f")),
            "0.1.0+g1a2b3c4d5e6f"
        );
        assert_eq!(v.product_string(None), "0.1.0");

        let v = Version::parse("1.20.300-rc.1").unwrap();
        assert_eq!(v.pre.as_deref(), Some("rc.1"));
        assert_eq!(v.quad(), [1, 20, 300, 0]);
        assert_eq!(v.msi().unwrap(), "1.20.300");
        assert_eq!(v.product_string(Some("abcdef0")), "1.20.300-rc.1+gabcdef0");

        let v = Version::parse("2.0.0-beta.2+local").unwrap();
        assert_eq!(v.build.as_deref(), Some("local"));
        assert_eq!(v.product_string(Some("abcdef0")), "2.0.0-beta.2+local");
        assert_eq!(v.to_string(), "2.0.0-beta.2+local");
    }

    #[test]
    fn rejects_what_the_version_resource_cannot_hold() {
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.2.x",
            "1.2.65536",
            "1.2.3-",
            "1.2.3-a..b",
            "1.2.3+",
            "1.2.3-a_b",
        ] {
            assert!(Version::parse(bad).is_err(), "{bad}");
        }
        assert!(Version::parse("256.0.0").unwrap().msi().is_err());
        assert!(Version::parse("0.256.0").unwrap().msi().is_err());
        assert_eq!(
            Version::parse("255.255.65535").unwrap().msi().unwrap(),
            "255.255.65535"
        );
    }

    #[test]
    fn recognises_short_commit_hashes() {
        assert!(is_commit("1a2b3c4d5e6f"));
        assert!(!is_commit("1a2b3c"));
        assert!(!is_commit("1A2B3C4D"));
        assert!(!is_commit("unknown"));
    }
}
