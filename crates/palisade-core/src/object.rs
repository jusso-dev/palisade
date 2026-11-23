//! Object classes: what kind of thing a decision is about.

use core::fmt;
use core::str::FromStr;

use crate::ParseError;

/// The kind of script, for [`ObjectType::Script`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ScriptKind {
    /// `.ps1`, `.psm1`, `.psd1`.
    Powershell,
    /// `.bat`.
    Batch,
    /// `.cmd`.
    Cmd,
    /// `.vbs`, `.vbe`.
    Vbscript,
    /// `.js`, `.jse` run by the OS script host.
    Jscript,
    /// `.wsf`.
    Wsf,
    /// `.wsc`, `.sct` scriptlets.
    Wsc,
    /// `.py`, `.pyw`, `.pyc`, `.pyo`.
    Python,
    /// `.jar`, `.class`.
    Java,
    /// `.reg` registry scripts.
    Reg,
    /// Any other interpreted script.
    Other,
}

impl ScriptKind {
    /// Every script kind, in declaration order.
    pub const ALL: [Self; 11] = [
        Self::Powershell,
        Self::Batch,
        Self::Cmd,
        Self::Vbscript,
        Self::Jscript,
        Self::Wsf,
        Self::Wsc,
        Self::Python,
        Self::Java,
        Self::Reg,
        Self::Other,
    ];

    /// The `snake_case` name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Powershell => "powershell",
            Self::Batch => "batch",
            Self::Cmd => "cmd",
            Self::Vbscript => "vbscript",
            Self::Jscript => "jscript",
            Self::Wsf => "wsf",
            Self::Wsc => "wsc",
            Self::Python => "python",
            Self::Java => "java",
            Self::Reg => "reg",
            Self::Other => "other",
        }
    }
}

/// The class of object being evaluated (ISM-1657, plus drivers for ISM-1658).
///
/// The text form is `snake_case`, and scripts are `script.<kind>`, for
/// example `executable` or `script.powershell`. The same spelling is used by
/// the per-type mode keys in #36. How a file's class is detected (content
/// first, extension second) is decided by #3 and #4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectType {
    /// Any PE image launched as a process, whatever its extension.
    Executable,
    /// A module loaded into a process (`.dll`, `.ocx`, `.pyd`, `.cpl` as a module).
    Library,
    /// A kernel image (`.sys`).
    Driver,
    /// An interpreted script.
    Script(ScriptKind),
    /// An installer package or patch (`.msi`, `.msp`, `.mst`, `.msu`, packaged-app install).
    Installer,
    /// Compiled HTML help (`.chm`).
    CompiledHtml,
    /// An HTML application (`.hta`).
    HtmlApplication,
    /// A control panel applet opened through the control panel host.
    ControlPanelApplet,
    /// Packaged-app activation.
    PackagedApp,
    /// An interpreter command or argument string evaluated as an object (#7).
    Command,
    /// COM class activation (reserved).
    ComObject,
}

impl ObjectType {
    /// Every object type, in declaration order, with every script kind.
    pub const ALL: [Self; 21] = [
        Self::Executable,
        Self::Library,
        Self::Driver,
        Self::Script(ScriptKind::Powershell),
        Self::Script(ScriptKind::Batch),
        Self::Script(ScriptKind::Cmd),
        Self::Script(ScriptKind::Vbscript),
        Self::Script(ScriptKind::Jscript),
        Self::Script(ScriptKind::Wsf),
        Self::Script(ScriptKind::Wsc),
        Self::Script(ScriptKind::Python),
        Self::Script(ScriptKind::Java),
        Self::Script(ScriptKind::Reg),
        Self::Script(ScriptKind::Other),
        Self::Installer,
        Self::CompiledHtml,
        Self::HtmlApplication,
        Self::ControlPanelApplet,
        Self::PackagedApp,
        Self::Command,
        Self::ComObject,
    ];

    /// The name. For a script this is the prefix `script`, and the full
    /// text form adds the kind.
    const fn name(self) -> &'static str {
        match self {
            Self::Executable => "executable",
            Self::Library => "library",
            Self::Driver => "driver",
            Self::Script(_) => "script",
            Self::Installer => "installer",
            Self::CompiledHtml => "compiled_html",
            Self::HtmlApplication => "html_application",
            Self::ControlPanelApplet => "control_panel_applet",
            Self::PackagedApp => "packaged_app",
            Self::Command => "command",
            Self::ComObject => "com_object",
        }
    }
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Script(kind) => write!(f, "script.{}", kind.as_str()),
            other => f.write_str(other.name()),
        }
    }
}

impl FromStr for ObjectType {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        if let Some(kind) = s.strip_prefix("script.") {
            return ScriptKind::ALL
                .into_iter()
                .find(|k| k.as_str() == kind)
                .map(Self::Script)
                .ok_or(ParseError("unknown script kind"));
        }
        Self::ALL
            .into_iter()
            .find(|t| !matches!(t, Self::Script(_)) && t.name() == s)
            .ok_or(ParseError("unknown object type"))
    }
}

crate::string_serde!(
    ObjectType,
    "an object type such as `executable` or `script.powershell`"
);

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ObjectType {
    fn schema_name() -> alloc::borrow::Cow<'static, str> {
        "ObjectType".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        use alloc::string::ToString;
        use alloc::vec::Vec;
        let names: Vec<_> = Self::ALL.iter().map(ToString::to_string).collect();
        schemars::json_schema!({
            "description": "The class of object being evaluated. Scripts are `script.<kind>`.",
            "type": "string",
            "enum": names
        })
    }
}
