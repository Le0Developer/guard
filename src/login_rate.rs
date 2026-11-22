use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

const REFILL: Duration = Duration::from_secs(60);
const BURST: f64 = 5.0;
const MAX_IPS: usize = 65_536;

struct Bucket {
    tokens: f64,
    updated: Instant,
}

pub(crate) struct LoginRate {
    state: Mutex<(HashMap<Option<IpAddr>, Bucket>, Instant)>,
}

impl Default for LoginRate {
    fn default() -> Self {
        Self {
            state: Mutex::new((HashMap::new(), Instant::now())),
        }
    }
}

impl LoginRate {
    /// Five initial attempts, then one replenished attempt per minute.
    pub fn check(&self, ip: Option<IpAddr>) -> Result<(), u64> {
        let now = Instant::now();
        let mut state = self.state.lock().expect("login rate limiter");
        let (buckets, pruned) = &mut *state;
        if now.duration_since(*pruned) >= REFILL {
            buckets.retain(|_, b| now.duration_since(b.updated) < REFILL * 5);
            *pruned = now;
        }
        // Keep memory bounded under traffic from many source addresses.
        if buckets.len() >= MAX_IPS && !buckets.contains_key(&ip) {
            return Err(60);
        }
        let bucket = buckets.entry(ip).or_insert(Bucket {
            tokens: BURST,
            updated: now,
        });
        bucket.tokens = (bucket.tokens
            + now.duration_since(bucket.updated).as_secs_f64() / REFILL.as_secs_f64())
        .min(BURST);
        bucket.updated = now;
        if bucket.tokens < 1.0 {
            return Err(((1.0 - bucket.tokens) * REFILL.as_secs_f64()).ceil() as u64);
        }
        bucket.tokens -= 1.0;
        Ok(())
    }
}
