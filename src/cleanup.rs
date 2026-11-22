use crate::{core::Core, models::*};
use std::{
    sync::{Arc, Weak},
    time::Duration,
};
use toasty_core::driver::operation::TransactionMode;

const INTERVAL: Duration = Duration::from_secs(5 * 60);
const BATCH: usize = 256;
const RETAIN_EXPIRED_FLOW_SECONDS: i64 = 24 * 3600;

pub(crate) fn spawn(core: &Arc<Core>) {
    tokio::spawn(run(Arc::downgrade(core)));
}

async fn run(core: Weak<Core>) {
    let mut delay = Duration::ZERO;
    let mut codes_after = i64::MIN;
    loop {
        tokio::time::sleep(delay).await;
        let Some(core) = core.upgrade() else { return };
        delay = match sweep(&core, &mut codes_after).await {
            // Drain backlogs without holding a write lock across batches or
            // postponing the remaining work for an entire interval.
            Ok(true) => Duration::from_secs(1),
            Ok(false) => INTERVAL,
            Err(_) => {
                eprintln!("Authentication cleanup failed; retrying in five minutes.");
                INTERVAL
            }
        };
    }
}

async fn sweep(core: &Core, codes_after: &mut i64) -> toasty::Result<bool> {
    let now = jiff::Timestamp::now();
    let before = |seconds| {
        jiff::Timestamp::from_second(now.as_second() - seconds).expect("recent cleanup cutoff")
    };
    let mut db = core.db.clone();
    let mut backlog = false;

    // Each table gets a short transaction. Recheck the predicate when deleting
    // so a concurrently renewed rate counter cannot be removed accidentally.
    macro_rules! prune {
        ($model:ident, $key:ident, $predicate:expr) => {{
            let predicate = $predicate;
            let mut tx = db
                .transaction_builder()
                .mode(TransactionMode::Immediate)
                .begin()
                .await?;
            let rows = $model::filter(predicate.clone())
                .limit(BATCH)
                .exec(&mut tx)
                .await?;
            backlog |= rows.len() == BATCH;
            if !rows.is_empty() {
                let keys: Vec<_> = rows.into_iter().map(|row| row.$key).collect();
                $model::filter(predicate.and($model::fields().$key().in_list(keys)))
                    .delete()
                    .exec(&mut tx)
                    .await?;
            }
            tx.commit().await?;
        }};
    }

    prune!(
        LoginSession,
        id,
        LoginSession::fields()
            .created_at()
            .le(before(crate::session::LOGIN_LIFETIME_SECONDS))
    );
    prune!(MfaCeremony, id, MfaCeremony::fields().expires_at().le(now));
    prune!(
        ForwardAuthRequest,
        id,
        ForwardAuthRequest::fields()
            .expires_at()
            .le(before(RETAIN_EXPIRED_FLOW_SECONDS))
    );
    prune!(
        ForwardAuthSession,
        id,
        ForwardAuthSession::fields().expires_at().le(now)
    );

    // Access-token expiry or rotation alone is insufficient: refresh tokens
    // and replay tombstones are needed until the entire family expires.
    prune!(OAuthToken, id, OAuthToken::fields().expires_at().le(now));
    // A consumed code remains the grant record used by reports and replay
    // protection. Keep it while ANY token row still refers to it. A keyset
    // cursor prevents retained grants from starving later unused codes.
    // Toasty 0.11 cannot lower a projected i64 foreign-key subquery here;
    // indexed existence counts avoid that unsupported cast.
    {
        let mut tx = db
            .transaction_builder()
            .mode(TransactionMode::Immediate)
            .begin()
            .await?;
        let codes = ClientToken::filter(
            ClientToken::fields()
                .expires_at()
                .le(now)
                .and(ClientToken::fields().id().gt(*codes_after)),
        )
        .order_by(ClientToken::fields().id().asc())
        .limit(BATCH)
        .exec(&mut tx)
        .await?;
        let full = codes.len() == BATCH;
        let mut last = i64::MIN;
        let mut unused = Vec::new();
        for code in codes {
            last = code.id;
            if OAuthToken::filter(OAuthToken::fields().code_id().eq(code.id))
                .count()
                .exec(&mut tx)
                .await?
                == 0
            {
                unused.push(code.id);
            }
        }
        if !unused.is_empty() {
            ClientToken::filter(ClientToken::fields().id().in_list(unused))
                .delete()
                .exec(&mut tx)
                .await?;
        }
        tx.commit().await?;
        *codes_after = if full { last } else { i64::MIN };
        backlog |= full;
    }
    prune!(
        Session,
        id,
        Session::fields()
            .created_at()
            .le(before(crate::session::LIFETIME_SECONDS))
    );
    prune!(
        ClientCryptographicKey,
        id,
        ClientCryptographicKey::fields().expires_at().le(before(60))
    );
    prune!(
        RecoveryCode,
        id,
        RecoveryCode::fields()
            .used_at()
            .le(Some(before(RETAIN_EXPIRED_FLOW_SECONDS)))
    );
    prune!(
        EventReportRate,
        client_id,
        EventReportRate::fields().window().lt(now.as_second() / 60)
    );

    // AuditLog, AccessLog and AccessLogDelivery are deliberately not pruned.
    Ok(backlog)
}
