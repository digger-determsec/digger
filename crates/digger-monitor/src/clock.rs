pub type Timestamp = u64;

pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> Timestamp {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

pub struct MockClock {
    current: Timestamp,
}

impl MockClock {
    pub fn new(start: Timestamp) -> Self {
        Self { current: start }
    }

    pub fn advance(&mut self, secs: u64) {
        self.current += secs;
    }

    pub fn set(&mut self, t: Timestamp) {
        self.current = t;
    }
}

impl Clock for MockClock {
    fn now(&self) -> Timestamp {
        self.current
    }
}
