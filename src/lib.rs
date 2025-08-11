use std::{
    sync::atomic::{AtomicBool, AtomicU64},
    time::Instant,
};

/// Tools for validating messages and data
pub mod validation;

#[derive(Debug)]
pub struct Preferences {
    sendheaders: AtomicBool,
    sendaddrv2: AtomicBool,
    sendcmpct: AtomicU64,
    sendwtxid: AtomicBool,
}

impl Preferences {
    fn new() -> Self {
        Self {
            sendheaders: AtomicBool::new(false),
            sendaddrv2: AtomicBool::new(false),
            sendcmpct: AtomicU64::new(0),
            sendwtxid: AtomicBool::new(false),
        }
    }

    fn prefers_header_announcment(&self) {
        self.sendheaders
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn prefers_addrv2(&self) {
        self.sendaddrv2
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn prefers_wtxid(&self) {
        self.sendwtxid
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn prefers_cmpct(&self, version: u64) {
        self.sendcmpct
            .store(version, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for Preferences {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum MessageRate {
    NoneReceived,
    Ongoing { count: f64, start: Instant },
}

impl MessageRate {
    fn new() -> Self {
        Self::NoneReceived
    }

    fn add_single_message(&mut self, now: Instant) {
        self.add_messages(1, now);
    }

    fn add_messages(&mut self, num_messages: usize, now: Instant) {
        if num_messages == 0 {
            return;
        }
        let num_messages = num_messages.try_into().unwrap_or(u32::MAX);
        let num_message_float_repr = num_messages.into();
        match self {
            Self::NoneReceived => {
                *self = Self::Ongoing {
                    count: num_message_float_repr,
                    start: now,
                }
            }
            Self::Ongoing { count, start: _ } => *count += num_message_float_repr,
        }
    }

    pub fn messages_per_secs(&self, now: Instant) -> Option<f64> {
        match self {
            Self::NoneReceived => None,
            Self::Ongoing { count, start } => {
                Some(*count / now.duration_since(*start).as_secs_f64())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use crate::{MessageRate, Preferences};

    #[test]
    fn test_message_rate() {
        let now = Instant::now();
        let later = now.checked_add(Duration::from_secs(10)).unwrap();
        let mut rate = MessageRate::new();
        rate.add_messages(0, now);
        assert!(matches!(rate, MessageRate::NoneReceived));
        rate.add_single_message(now);
        rate.add_messages(9, later);
        assert_eq!(rate.messages_per_secs(later).unwrap(), 1.);
        rate.add_messages(10, later);
        assert_eq!(rate.messages_per_secs(later).unwrap(), 2.);
    }

    #[test]
    fn test_preferences() {
        let pref = Preferences::new();
    }
}
