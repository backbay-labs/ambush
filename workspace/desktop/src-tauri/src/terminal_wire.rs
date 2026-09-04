//! The typed wire shapes the terminal transport puts on the IPC channel.
//!
//! Split out of `terminal_runtime.rs` when that file crossed the 1000-line
//! ratchet. A clean seam: everything here is a serialisation shape or a
//! conversion between one and an engine type, and none of it touches a PTY.

use ambush_terminal::damage::Style;
use ambush_terminal::Viewport;
use serde::{Deserialize, Serialize};

use crate::terminal_transport::Publication;

type Result<T> = std::result::Result<T, String>;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireViewport {
    pub(crate) generation: u64,
    pub(crate) columns: usize,
    pub(crate) screen_lines: usize,
}

impl From<Viewport> for WireViewport {
    fn from(value: Viewport) -> Self {
        Self {
            generation: value.generation,
            columns: value.columns,
            screen_lines: value.screen_lines,
        }
    }
}

impl From<WireViewport> for Viewport {
    fn from(value: WireViewport) -> Self {
        Self {
            generation: value.generation,
            columns: value.columns,
            screen_lines: value.screen_lines,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AttachResponse {
    pub(crate) session_id: String,
    pub(crate) subscription_id: String,
    pub(crate) viewport: WireViewport,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireStyle {
    pub(crate) fg: u32,
    pub(crate) bg: u32,
    pub(crate) flags: u16,
}

impl From<Style> for WireStyle {
    fn from(value: Style) -> Self {
        Self {
            fg: value.fg,
            bg: value.bg,
            flags: value.flags,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireCluster {
    pub(crate) column: usize,
    pub(crate) text: String,
    pub(crate) width: u8,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireSpan {
    pub(crate) style: WireStyle,
    pub(crate) clusters: Vec<WireCluster>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireRow {
    pub(crate) line: usize,
    pub(crate) wrapped: bool,
    pub(crate) spans: Vec<WireSpan>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WireCursor {
    pub(crate) line: usize,
    pub(crate) column: usize,
    pub(crate) visible: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FrameMessage {
    pub(crate) subscription_id: String,
    pub(crate) sequence: u64,
    pub(crate) rows: Vec<WireRow>,
    pub(crate) cursor: WireCursor,
    pub(crate) full: bool,
    pub(crate) viewport: WireViewport,
    pub(crate) bracketed_paste: bool,
    pub(crate) focus_reporting: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", content = "payload", rename_all = "camelCase")]
pub(crate) enum TerminalMessage {
    Frame(FrameMessage),
    Title(String),
    ResetTitle,
    Bell,
    Exit,
}

pub(crate) fn wire_publication(publication: Publication) -> Result<FrameMessage> {
    let frame = publication.frame;
    let rows = frame
        .rows
        .into_iter()
        .map(|row| {
            let spans = row
                .spans
                .into_iter()
                .map(|span| {
                    if !span.counts_are_consistent() {
                        return Err(
                            "terminal engine emitted an inconsistent cluster count".to_string()
                        );
                    }
                    let clusters = if span.cluster_count == 1 {
                        vec![WireCluster {
                            column: span.column,
                            text: span.text,
                            width: span.width,
                        }]
                    } else {
                        span.text
                            .chars()
                            .enumerate()
                            .map(|(index, ch)| WireCluster {
                                column: span.column + index * usize::from(span.width),
                                text: ch.to_string(),
                                width: span.width,
                            })
                            .collect()
                    };
                    Ok(WireSpan {
                        style: span.style.into(),
                        clusters,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(WireRow {
                line: row.line,
                wrapped: row.wrapped,
                spans,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(FrameMessage {
        subscription_id: publication.subscription_id.to_string(),
        sequence: publication.sequence,
        rows,
        cursor: WireCursor {
            line: frame.cursor.line,
            column: frame.cursor.column,
            visible: frame.cursor.visible,
        },
        full: frame.full,
        viewport: frame.viewport.into(),
        bracketed_paste: false,
        focus_reporting: false,
    })
}
