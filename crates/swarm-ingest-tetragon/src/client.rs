use crate::error::{Error, Result};
use tonic::transport::Channel;

#[allow(clippy::large_enum_variant)]
pub mod proto {
    tonic::include_proto!("tetragon");
}

pub use proto::fine_guidance_sensors_client::FineGuidanceSensorsClient;
pub use proto::{
    EventType, Filter, GetEventsRequest, GetEventsResponse, ProcessExec, ProcessExit, ProcessKprobe,
};

pub struct TetragonClient {
    inner: FineGuidanceSensorsClient<Channel>,
}

impl TetragonClient {
    pub async fn connect(endpoint: &str) -> Result<Self> {
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|error| Error::Grpc(format!("invalid endpoint: {error}")))?
            .connect()
            .await
            .map_err(|error| Error::Grpc(format!("failed to connect: {error}")))?;
        Ok(Self {
            inner: FineGuidanceSensorsClient::new(channel),
        })
    }

    pub async fn get_events(
        &mut self,
        allow_list: Vec<EventType>,
        deny_list: Vec<EventType>,
    ) -> Result<tonic::Streaming<GetEventsResponse>> {
        let allow_filters = if allow_list.is_empty() {
            Vec::new()
        } else {
            vec![Filter {
                event_set: allow_list.into_iter().map(|event| event as i32).collect(),
                ..Default::default()
            }]
        };
        let deny_filters = if deny_list.is_empty() {
            Vec::new()
        } else {
            vec![Filter {
                event_set: deny_list.into_iter().map(|event| event as i32).collect(),
                ..Default::default()
            }]
        };
        let request = GetEventsRequest {
            allow_list: allow_filters,
            deny_list: deny_filters,
            aggregation_options: None,
            field_filters: Vec::new(),
        };
        let response = self
            .inner
            .get_events(request)
            .await
            .map_err(|error| Error::Grpc(format!("GetEvents RPC failed: {error}")))?;
        Ok(response.into_inner())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TetragonEventKind {
    ProcessExec,
    ProcessExit,
    ProcessKprobe,
    Unknown,
}

pub fn classify_event(response: &GetEventsResponse) -> TetragonEventKind {
    match &response.event {
        Some(proto::get_events_response::Event::ProcessExec(_)) => TetragonEventKind::ProcessExec,
        Some(proto::get_events_response::Event::ProcessExit(_)) => TetragonEventKind::ProcessExit,
        Some(proto::get_events_response::Event::ProcessKprobe(_)) => {
            TetragonEventKind::ProcessKprobe
        }
        None => TetragonEventKind::Unknown,
    }
}
