//! A real-time ETW session for the process monitor (#59).
//!
//! Thin wrappers over `StartTraceW`, `EnableTraceEx2`, `ControlTraceW`,
//! `OpenTraceW`, `ProcessTrace` and `CloseTrace`. The record callback copies
//! each record's header fields and user data into a
//! [`RawEvent`](crate::telemetry::kernel::RawEvent) and hands it to a
//! closure; it interprets nothing. Decoding is in the portable
//! `telemetry::kernel`, which is tested and fuzzed on every OS.
//!
//! The session is one global named session, so [`Session::start`] stops a
//! stale session of the same name (left by a crash) and starts again.

#![allow(unsafe_code)]

use std::io;

use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_CTX_CLOSE_PENDING, ERROR_SUCCESS, ERROR_WMI_INSTANCE_NOT_FOUND,
    WIN32_ERROR,
};
use windows_sys::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_HEADER_FLAG_32_BIT_HEADER, EVENT_RECORD, EVENT_TRACE_CONTROL, EVENT_TRACE_CONTROL_QUERY,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_LOGFILEW_0, EVENT_TRACE_LOGFILEW_1,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    ProcessTrace, StartTraceW, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};
use windows_sys::core::GUID;

use crate::telemetry::kernel::RawEvent;

/// `INVALID_PROCESSTRACE_HANDLE`.
const INVALID_PROCESSTRACE_HANDLE: u64 = u64::MAX;

/// `WNODE_HEADER.ClientContext` 1: query performance counter timestamps
/// are not wanted; 1 is the system time (100 ns `FILETIME`s).
const CLOCK_SYSTEM_TIME: u32 = 1;

/// Buffer sizes for the session, in KiB and counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Buffers {
    pub(crate) size_kb: u32,
    pub(crate) min: u32,
    pub(crate) max: u32,
}

/// What the OS reports about a running session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SessionStats {
    pub(crate) events_lost: u32,
    pub(crate) realtime_buffers_lost: u32,
    pub(crate) log_buffers_lost: u32,
}

fn wide(name: &str) -> Vec<u16> {
    name.encode_utf16().chain([0]).collect()
}

fn guid(value: u128) -> GUID {
    GUID::from_u128(value)
}

fn win32(code: WIN32_ERROR, what: &str) -> io::Error {
    let e = io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX));
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

/// `EVENT_TRACE_PROPERTIES` followed by room for the session name, as the
/// OS requires, in a buffer aligned for the structure.
struct Properties {
    words: Vec<u64>,
}

impl Properties {
    fn new(name: &[u16], buffers: Option<Buffers>) -> Self {
        let head = size_of::<EVENT_TRACE_PROPERTIES>();
        let total = head + name.len() * 2;
        let words = vec![0_u64; total.div_ceil(8)];
        let mut p = Self { words };
        let props = p.props_mut();
        props.Wnode.BufferSize = u32::try_from(total).unwrap_or(u32::MAX);
        props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props.Wnode.ClientContext = CLOCK_SYSTEM_TIME;
        props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props.LoggerNameOffset = u32::try_from(head).unwrap_or(u32::MAX);
        if let Some(b) = buffers {
            props.BufferSize = b.size_kb;
            props.MinimumBuffers = b.min;
            props.MaximumBuffers = b.max;
            props.FlushTimer = 1;
        }
        p
    }

    fn props_mut(&mut self) -> &mut EVENT_TRACE_PROPERTIES {
        // SAFETY: `words` holds at least `size_of::<EVENT_TRACE_PROPERTIES>()`
        // bytes, is 8-byte aligned (enough for the structure, whose largest
        // field is 8 bytes) and zero-initialised, which is a valid value of
        // this plain-data structure. The borrow of `self` keeps it unique.
        unsafe { &mut *self.words.as_mut_ptr().cast::<EVENT_TRACE_PROPERTIES>() }
    }

    fn as_mut_ptr(&mut self) -> *mut EVENT_TRACE_PROPERTIES {
        self.words.as_mut_ptr().cast()
    }
}

/// Runs `ControlTraceW` with `code` on the session `name`.
fn control(name: &[u16], code: EVENT_TRACE_CONTROL) -> (WIN32_ERROR, SessionStats) {
    let mut props = Properties::new(name, None);
    // SAFETY: `name` is NUL-terminated; `props` is a live, writable,
    // aligned buffer whose `Wnode.BufferSize` is its size and which has
    // room for the name at `LoggerNameOffset`, as the call requires.
    let status = unsafe {
        ControlTraceW(
            CONTROLTRACE_HANDLE { Value: 0 },
            name.as_ptr(),
            props.as_mut_ptr(),
            code,
        )
    };
    let p = props.props_mut();
    let stats = SessionStats {
        events_lost: p.EventsLost,
        realtime_buffers_lost: p.RealTimeBuffersLost,
        log_buffers_lost: p.LogBuffersLost,
    };
    (status, stats)
}

/// A running real-time session. Stopped on drop.
pub(crate) struct Session {
    name: Vec<u16>,
    handle: CONTROLTRACE_HANDLE,
}

impl Session {
    /// Starts the session `name`, stopping a stale one of the same name.
    pub(crate) fn start(name: &str, buffers: Buffers) -> io::Result<Self> {
        let name = wide(name);
        for attempt in 0..2 {
            let mut props = Properties::new(&name, Some(buffers));
            let mut handle = CONTROLTRACE_HANDLE { Value: 0 };
            // SAFETY: `handle` is a live local the OS writes; `name` is
            // NUL-terminated; `props` is set up as in `control`.
            let status = unsafe { StartTraceW(&raw mut handle, name.as_ptr(), props.as_mut_ptr()) };
            match status {
                ERROR_SUCCESS => return Ok(Self { name, handle }),
                ERROR_ALREADY_EXISTS if attempt == 0 => {
                    let (stop, _) = control(&name, EVENT_TRACE_CONTROL_STOP);
                    if stop != ERROR_SUCCESS && stop != ERROR_WMI_INSTANCE_NOT_FOUND {
                        return Err(win32(stop, "stop the stale trace session"));
                    }
                }
                other => return Err(win32(other, "start the trace session")),
            }
        }
        Err(win32(ERROR_ALREADY_EXISTS, "start the trace session"))
    }

    /// Enables `provider` with `keywords` at the information level.
    pub(crate) fn enable(&self, provider: u128, keywords: u64) -> io::Result<()> {
        let id = guid(provider);
        // SAFETY: `self.handle` is a running session; `id` is a live local;
        // no enable parameters are passed (null is allowed).
        let status = unsafe {
            EnableTraceEx2(
                self.handle,
                &raw const id,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                u8::try_from(TRACE_LEVEL_INFORMATION).unwrap_or(4),
                keywords,
                0,
                0,
                std::ptr::null(),
            )
        };
        if status == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(win32(status, "enable the provider"))
        }
    }

    /// The session's loss counters.
    pub(crate) fn stats(&self) -> io::Result<SessionStats> {
        let (status, stats) = control(&self.name, EVENT_TRACE_CONTROL_QUERY);
        if status == ERROR_SUCCESS {
            Ok(stats)
        } else {
            Err(win32(status, "query the trace session"))
        }
    }

    /// A handle that stops the session from another thread.
    pub(crate) fn stopper(&self) -> Stopper {
        Stopper {
            name: self.name.clone(),
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = control(&self.name, EVENT_TRACE_CONTROL_STOP);
    }
}

/// Stops a session by name, which ends its `ProcessTrace` loop.
#[derive(Clone, Debug)]
pub(crate) struct Stopper {
    name: Vec<u16>,
}

impl Stopper {
    /// Stops the session. Stopping one that has already stopped is fine.
    pub(crate) fn stop(&self) {
        let _ = control(&self.name, EVENT_TRACE_CONTROL_STOP);
    }
}

/// The per-consumer state the callback reaches through `UserContext`.
struct Context<'a> {
    on_event: &'a mut dyn FnMut(RawEvent),
}

unsafe extern "system" fn record_callback(record: *mut EVENT_RECORD) {
    // SAFETY: the OS passes a valid record for the duration of the call.
    let Some(record) = (unsafe { record.as_ref() }) else {
        return;
    };
    // SAFETY: `UserContext` is the `Context` that `consume` set in the
    // log file's `Context`, which outlives `ProcessTrace`, the only caller
    // of this callback; ETW calls it on that one thread, so the mutable
    // borrow is unique.
    let Some(context) = (unsafe { record.UserContext.cast::<Context<'_>>().as_mut() }) else {
        return;
    };
    let len = usize::from(record.UserDataLength);
    let data = if len == 0 || record.UserData.is_null() {
        Vec::new()
    } else {
        // SAFETY: the OS guarantees `UserData` points at `UserDataLength`
        // readable bytes for the duration of the call; they are copied.
        unsafe { std::slice::from_raw_parts(record.UserData.cast::<u8>(), len) }.to_vec()
    };
    let h = &record.EventHeader;
    let g = h.ProviderId;
    let provider = u128::from(g.data1) << 96
        | u128::from(g.data2) << 80
        | u128::from(g.data3) << 64
        | u128::from(u64::from_be_bytes(g.data4));
    let pointer_size = if u32::from(h.Flags) & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
        4
    } else {
        8
    };
    let raw = RawEvent {
        provider,
        id: h.EventDescriptor.Id,
        version: h.EventDescriptor.Version,
        pointer_size,
        header_pid: h.ProcessId,
        header_tid: h.ThreadId,
        timestamp: u64::try_from(h.TimeStamp).unwrap_or(0),
        data,
    };
    // A panic must not unwind into the OS.
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (context.on_event)(raw)));
}

/// Consumes the real-time session `name` on this thread, calling
/// `on_event` for each record, until the session stops.
pub(crate) fn consume(name: &str, on_event: &mut dyn FnMut(RawEvent)) -> io::Result<()> {
    let mut name = wide(name);
    let mut context = Context { on_event };
    let mut logfile = EVENT_TRACE_LOGFILEW {
        LoggerName: name.as_mut_ptr(),
        Anonymous1: EVENT_TRACE_LOGFILEW_0 {
            ProcessTraceMode: PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD,
        },
        Anonymous2: EVENT_TRACE_LOGFILEW_1 {
            EventRecordCallback: Some(record_callback),
        },
        Context: (&raw mut context).cast(),
        ..EVENT_TRACE_LOGFILEW::default()
    };
    // SAFETY: `logfile` is a live, initialised structure; `name` and
    // `context` outlive the handle, which is closed below before either is
    // dropped.
    let handle = unsafe { OpenTraceW(&raw mut logfile) };
    if handle.Value == INVALID_PROCESSTRACE_HANDLE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: one valid handle; no time window (null start and end). The
    // call returns when the session stops.
    let status = unsafe { ProcessTrace(&raw const handle, 1, std::ptr::null(), std::ptr::null()) };
    // SAFETY: `handle` came from `OpenTraceW` and is closed once.
    let close = unsafe {
        CloseTrace(PROCESSTRACE_HANDLE {
            Value: handle.Value,
        })
    };
    if status != ERROR_SUCCESS && status != ERROR_CTX_CLOSE_PENDING {
        return Err(win32(status, "consume the trace session"));
    }
    if close != ERROR_SUCCESS && close != ERROR_CTX_CLOSE_PENDING {
        return Err(win32(close, "close the trace session"));
    }
    Ok(())
}
