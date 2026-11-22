use super::*;
use std::time::Duration;

pub(super) async fn run(core: Arc<Core>) {
    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Access journal exporter could not initialize; delivery remains pending.");
            return;
        }
    };
    loop {
        match batch(&core, &client).await {
            Ok(true) => tokio::task::yield_now().await,
            Ok(false) => tokio::time::sleep(Duration::from_secs(1)).await,
            Err(()) => {
                eprintln!("Access journal export failed; undelivered records remain queued.");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}
async fn batch(core: &Core, client: &reqwest::Client) -> std::result::Result<bool, ()> {
    let mut db = core.db.clone();
    let deliveries = AccessLogDelivery::filter(
        AccessLogDelivery::fields().delivered_at().is_none().and(
            AccessLogDelivery::fields()
                .next_attempt_at()
                .le(jiff::Timestamp::now()),
        ),
    )
    .order_by(AccessLogDelivery::fields().log_id().asc())
    .limit(100)
    .exec(&mut db)
    .await
    .map_err(|_| ())?;
    if deliveries.is_empty() {
        return Ok(false);
    }
    let mut events = Vec::new();
    for delivery in &deliveries {
        let log = AccessLog::get_by_id(&mut db, delivery.log_id).await;
        let log = match log {
            Ok(log) => log,
            Err(_) => return Err(()),
        };
        events.push(json!({"event_id":log.event_id,"sequence":log.id,"received_at":log.created_at,"client_id":log.client_id,"user_id":log.user_id,"session_id":log.session_id,"source":log.source,"data":log.data.0}));
    }
    let mut request = client
        .post(
            core.journal_config
                .export_url
                .as_ref()
                .expect("configured collector")
                .clone(),
        )
        .json(&json!({"version":1,"instance":core.domain,"events":events}));
    if let Some(token) = &core.journal_config.export_token {
        request = request.bearer_auth(token);
    }
    let outcome = match request.send().await {
        Ok(response) if response.status().is_success() => None,
        Ok(response) => Some(format!("HTTP {}", response.status().as_u16())),
        Err(_) => Some("Transport failure".into()),
    };
    let mut tx = db.transaction().await.map_err(|_| ())?;
    for delivery in &deliveries {
        let attempts = delivery.attempts.saturating_add(1);
        if let Some(error) = &outcome {
            let delay = 2i64.pow(attempts.min(8)).min(300);
            let retry = jiff::Timestamp::from_second(jiff::Timestamp::now().as_second() + delay)
                .map_err(|_| ())?;
            AccessLogDelivery::filter_by_log_id(delivery.log_id)
                .update()
                .attempts(attempts)
                .next_attempt_at(retry)
                .last_error(error)
                .exec(&mut tx)
                .await
                .map_err(|_| ())?;
        } else {
            AccessLogDelivery::filter_by_log_id(delivery.log_id)
                .update()
                .attempts(attempts)
                .delivered_at(jiff::Timestamp::now())
                .last_error(None::<String>)
                .exec(&mut tx)
                .await
                .map_err(|_| ())?;
        }
    }
    tx.commit().await.map_err(|_| ())?;
    if outcome.is_some() { Err(()) } else { Ok(true) }
}
