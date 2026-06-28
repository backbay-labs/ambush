use std::future::Future;

tokio::task_local! {
    static TRACE_ID: String;
}

pub async fn with_trace_id<F, T>(trace_id: impl Into<String>, future: F) -> T
where
    F: Future<Output = T>,
{
    TRACE_ID.scope(trace_id.into(), future).await
}

pub fn current_trace_id() -> Option<String> {
    TRACE_ID.try_with(Clone::clone).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{current_trace_id, with_trace_id};

    #[tokio::test(flavor = "current_thread")]
    async fn trace_id_is_visible_inside_scope_and_cleared_afterward() {
        assert!(current_trace_id().is_none());

        let seen = with_trace_id("trace-123", async {
            tokio::task::yield_now().await;
            current_trace_id()
        })
        .await;

        assert_eq!(seen.as_deref(), Some("trace-123"));
        assert!(current_trace_id().is_none());
    }
}
