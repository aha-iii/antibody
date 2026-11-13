use nerve_waf_core::InspectTimingReport;
use serde_json::json;

pub struct InspectTraceMeta {
    pub method: String,
    pub host: String,
    pub uri: String,
    pub src_ip: String,
    pub trace_id: Option<String>,
}

pub fn emit_inspect_trace_log(report: &InspectTimingReport, meta: &InspectTraceMeta) {
    let line = json!({
        "event": "inspect_node_trace",
        "method": meta.method,
        "host": meta.host,
        "uri": meta.uri,
        "src_ip": meta.src_ip,
        "trace_id": meta.trace_id,
        "total_us": report.total_us,
        "path": report.path,
        "blocked": report.blocked,
        "nodes": report.nodes,
    });
    tracing::info!(target: "inspect_trace", "{}", line);
}
