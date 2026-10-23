//! 윈도·메모리·제어 큐를 분리하여 느린 스트림이 다른 읽기를 막지 않게 한다.
use crate::{Code, Frame};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Instant;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_util::sync::CancellationToken;

pub struct SendWindow {
    pub permits: Arc<Semaphore>,
    outstanding: AtomicUsize,
    pub notify: Notify,
    pub max: usize,
}
impl SendWindow {
    pub fn new(n: u32) -> Arc<Self> {
        Arc::new(Self {
            permits: Arc::new(Semaphore::new(n as usize)),
            outstanding: AtomicUsize::new(0),
            notify: Notify::new(),
            max: n as usize,
        })
    }
    pub fn update(&self, n: u32) -> Result<(), Code> {
        let n = n as usize;
        if n == 0 || n > self.max {
            return Err(Code::Protocol);
        }
        self.outstanding
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_sub(n))
            .map_err(|_| Code::Protocol)?;
        self.permits.add_permits(n);
        self.notify.notify_waiters();
        Ok(())
    }
}
pub struct Reservation {
    connection: Arc<SendWindow>,
    stream: Arc<SendWindow>,
    cp: OwnedSemaphorePermit,
    sp: OwnedSemaphorePermit,
}
impl Reservation {
    pub async fn reserve(
        connection: Arc<SendWindow>,
        stream: Arc<SendWindow>,
        max_data: usize,
    ) -> Result<(Self, usize), Code> {
        loop {
            let a = connection.notify.notified();
            let b = stream.notify.notified();
            let data = connection
                .permits
                .available_permits()
                .min(stream.permits.available_permits())
                .saturating_sub(64)
                .min(max_data);
            if data == 0 {
                tokio::select! {_=a=>{},_=b=>{}}
                continue;
            }
            drop(a);
            drop(b);
            let size = (data + 64) as u32;
            let sp = stream
                .permits
                .clone()
                .acquire_many_owned(size)
                .await
                .map_err(|_| Code::Io)?;
            let cp = connection
                .permits
                .clone()
                .acquire_many_owned(size)
                .await
                .map_err(|_| Code::Io)?;
            return Ok((
                Self {
                    connection,
                    stream,
                    cp,
                    sp,
                },
                data,
            ));
        }
    }
    /// 데이터그램 경계를 유지하며 반환되는 전송 윈도를 기다린다. 취소하면 확보한 크레딧도 돌려준다.
    pub async fn exact(
        connection: Arc<SendWindow>,
        stream: Arc<SendWindow>,
        cost: u32,
    ) -> Result<Self, Code> {
        if cost as usize > connection.max || cost as usize > stream.max {
            return Err(Code::TooLarge);
        }
        let sp = stream
            .permits
            .clone()
            .acquire_many_owned(cost)
            .await
            .map_err(|_| Code::Io)?;
        let cp = connection
            .permits
            .clone()
            .acquire_many_owned(cost)
            .await
            .map_err(|_| Code::Io)?;
        Ok(Self {
            connection,
            stream,
            cp,
            sp,
        })
    }
    pub fn immediate(
        connection: Arc<SendWindow>,
        stream: Arc<SendWindow>,
        cost: u32,
    ) -> Result<Self, Code> {
        let sp = stream
            .permits
            .clone()
            .try_acquire_many_owned(cost)
            .map_err(|_| Code::Resource)?;
        let cp = connection
            .permits
            .clone()
            .try_acquire_many_owned(cost)
            .map_err(|_| Code::Resource)?;
        Ok(Self {
            connection,
            stream,
            cp,
            sp,
        })
    }
    pub fn shrink(&mut self, cost: usize) {
        let n = self.cp.num_permits() - cost;
        if n > 0 {
            drop(self.cp.split(n));
            drop(self.sp.split(n));
        }
    }
    pub fn commit(self) {
        let n = self.cp.num_permits();
        self.connection.outstanding.fetch_add(n, Ordering::SeqCst);
        self.stream.outstanding.fetch_add(n, Ordering::SeqCst);
        self.cp.forget();
        self.sp.forget();
    }
}
#[derive(Clone)]
pub struct Budget {
    pub global: Arc<Semaphore>,
    pub user: Arc<Semaphore>,
    pub connection: Arc<Semaphore>,
}
pub struct Charge {
    _global: OwnedSemaphorePermit,
    _user: OwnedSemaphorePermit,
    _connection: OwnedSemaphorePermit,
}
impl Budget {
    pub fn charge(&self, n: usize) -> Result<Charge, Code> {
        let n = u32::try_from(n).map_err(|_| Code::Resource)?;
        Ok(Charge {
            _global: self
                .global
                .clone()
                .try_acquire_many_owned(n)
                .map_err(|_| Code::Resource)?,
            _user: self
                .user
                .clone()
                .try_acquire_many_owned(n)
                .map_err(|_| Code::Resource)?,
            _connection: self
                .connection
                .clone()
                .try_acquire_many_owned(n)
                .map_err(|_| Code::Resource)?,
        })
    }
}
pub struct Queued {
    pub stream_cancel: Option<CancellationToken>,
    pub frame: Frame,
    pub credit: Option<Reservation>,
    pub _charge: Charge,
}
#[derive(Clone)]
pub struct Sender {
    pub stream_cancel: Option<CancellationToken>,
    pub control: mpsc::Sender<Frame>,
    pub data: mpsc::Sender<Queued>,
    pub cancel: CancellationToken,
    pub budget: Budget,
}
impl Sender {
    pub fn control(&self, f: Frame) -> Result<(), Code> {
        self.control.try_send(f).map_err(|_| {
            self.cancel.cancel();
            Code::Resource
        })
    }
    pub async fn data(&self, frame: Frame, credit: Option<Reservation>) -> Result<(), Code> {
        let charge = self.budget.charge(frame.payload.len() + 64)?;
        self.data
            .send(Queued {
                stream_cancel: self.stream_cancel.clone(),
                frame,
                credit,
                _charge: charge,
            })
            .await
            .map_err(|_| Code::Io)
    }
    pub fn datagram(&self, frame: Frame, credit: Reservation) -> Result<(), Code> {
        let charge = self.budget.charge(frame.payload.len() + 64)?;
        self.data
            .try_send(Queued {
                stream_cancel: self.stream_cancel.clone(),
                frame,
                credit: Some(credit),
                _charge: charge,
            })
            .map_err(|_| Code::Resource)
    }
}
pub struct ReceiveWindow {
    remaining: AtomicUsize,
    pending: AtomicUsize,
    max: usize,
}
impl ReceiveWindow {
    pub fn new(n: u32) -> Arc<Self> {
        Arc::new(Self {
            remaining: AtomicUsize::new(n as usize),
            pending: AtomicUsize::new(0),
            max: n as usize,
        })
    }
    fn consume(&self, n: u32) -> Result<(), Code> {
        self.remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
                v.checked_sub(n as usize)
            })
            .map(|_| ())
            .map_err(|_| Code::Protocol)
    }
    fn restore(&self, n: u32) {
        let old = self.remaining.fetch_add(n as usize, Ordering::SeqCst);
        debug_assert!(old + n as usize <= self.max);
    }
    pub fn take_pending(&self) -> u32 {
        let n = self.pending.swap(0, Ordering::SeqCst) as u32;
        if n > 0 {
            self.restore(n);
        }
        n
    }
}
pub struct Acknowledgement {
    n: u32,
    connection: Arc<ReceiveWindow>,
    stream: Arc<ReceiveWindow>,
}
impl Acknowledgement {
    pub fn take(
        n: u32,
        connection: Arc<ReceiveWindow>,
        stream: Arc<ReceiveWindow>,
    ) -> Result<Self, Code> {
        connection.consume(n)?;
        if let Err(e) = stream.consume(n) {
            connection.restore(n);
            return Err(e);
        }
        Ok(Self {
            n,
            connection,
            stream,
        })
    }
}
impl Drop for Acknowledgement {
    fn drop(&mut self) {
        self.connection
            .pending
            .fetch_add(self.n as usize, Ordering::SeqCst);
        self.stream
            .pending
            .fetch_add(self.n as usize, Ordering::SeqCst);
    }
}

pub struct Rate {
    state: Mutex<(f64, Instant)>,
    per_second: f64,
    capacity: f64,
}
impl Rate {
    pub fn new(rate: u64) -> Self {
        Self {
            state: Mutex::new((rate as f64, Instant::now())),
            per_second: rate as f64,
            capacity: rate as f64,
        }
    }
    pub fn take(&self, n: u64) -> bool {
        let Ok(mut s) = self.state.lock() else {
            return false;
        };
        let now = Instant::now();
        s.0 = (s.0 + now.duration_since(s.1).as_secs_f64() * self.per_second).min(self.capacity);
        s.1 = now;
        if s.0 >= n as f64 {
            s.0 -= n as f64;
            true
        } else {
            false
        }
    }
    pub async fn wait(&self, n: u64) {
        while !self.take(n) {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn 윈도_초과반환_거부() {
        let w = SendWindow::new(65536);
        assert_eq!(w.update(1), Err(Code::Protocol));
        assert_eq!(w.update(0), Err(Code::Protocol));
    }
    #[tokio::test]
    async fn 예약취소와_실제소비() {
        let a = SendWindow::new(65536);
        let b = SendWindow::new(65536);
        {
            let (r, n) = Reservation::reserve(a.clone(), b.clone(), 1024)
                .await
                .unwrap();
            assert_eq!(n, 1024);
            drop(r);
        }
        assert_eq!(a.permits.available_permits(), 65536);
        let (mut r, _) = Reservation::reserve(a.clone(), b.clone(), 1024)
            .await
            .unwrap();
        r.shrink(100);
        r.commit();
        a.update(100).unwrap();
        b.update(100).unwrap();
        assert_eq!(a.permits.available_permits(), 65536);
    }
}
