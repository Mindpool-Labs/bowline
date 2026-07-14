use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use bowline_core::quality_run::{
    QualityOutcome, QualityProvenance, QualityRunManifest, QualityRunPlan, QualityRunStore,
};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone)]
pub struct ManagedQualityWriterOptions {
    pub root: PathBuf,
    pub provenance: QualityProvenance,
    pub plan: QualityRunPlan,
    pub queue_capacity: usize,
}

#[derive(Clone)]
pub struct ManagedQualityWriter {
    inner: Arc<Inner>,
}

struct Inner {
    store: Arc<QualityRunStore>,
    tx: mpsc::Sender<Message>,
    join: Mutex<Option<thread::JoinHandle<()>>>,
}

enum Message {
    Outcome(Box<QualityOutcome>),
    Shutdown {
        cancelled: bool,
        reply: oneshot::Sender<Result<QualityRunManifest, String>>,
    },
}

#[derive(Debug, Error)]
pub enum ManagedQualityWriterError {
    #[error("quality writer queue is full")]
    QueueFull,
    #[error("quality writer is closed")]
    Closed,
    #[error("quality writer shutdown exceeded grace period")]
    ShutdownTimeout,
    #[error("quality writer failed: {0}")]
    Writer(String),
    #[error(transparent)]
    Store(#[from] bowline_core::quality_run::QualityRunError),
}

pub fn spawn_managed_quality_writer(
    options: ManagedQualityWriterOptions,
) -> Result<ManagedQualityWriter, ManagedQualityWriterError> {
    spawn_inner(options, None)
}

#[cfg(test)]
pub(crate) fn spawn_paused_managed_quality_writer(
    options: ManagedQualityWriterOptions,
) -> Result<(ManagedQualityWriter, std::sync::mpsc::Sender<()>), ManagedQualityWriterError> {
    let (release, wait) = std::sync::mpsc::channel();
    Ok((spawn_inner(options, Some(wait))?, release))
}

fn spawn_inner(
    options: ManagedQualityWriterOptions,
    pause: Option<std::sync::mpsc::Receiver<()>>,
) -> Result<ManagedQualityWriter, ManagedQualityWriterError> {
    if options.queue_capacity == 0 {
        return Err(ManagedQualityWriterError::Writer(
            "queue capacity must be positive".into(),
        ));
    }
    let store = Arc::new(QualityRunStore::create_under(
        &options.root,
        options.provenance,
        options.plan,
    )?);
    let (ledger, recovery) = store.open_ledger()?;
    if !matches!(
        recovery,
        bowline_core::quality_run::QualityRecovery::Absent
            | bowline_core::quality_run::QualityRecovery::Clean { records: 0 }
    ) {
        store.set_writer_error();
        return Err(ManagedQualityWriterError::Writer(
            "new quality ledger was not empty".into(),
        ));
    }
    store.flush()?;
    let (tx, rx) = mpsc::channel(options.queue_capacity);
    let thread_store = Arc::clone(&store);
    let join = thread::Builder::new()
        .name("bowline-quality-writer".into())
        .spawn(move || writer_thread(thread_store, ledger, rx, pause))
        .map_err(|error| ManagedQualityWriterError::Writer(error.to_string()))?;
    Ok(ManagedQualityWriter {
        inner: Arc::new(Inner {
            store,
            tx,
            join: Mutex::new(Some(join)),
        }),
    })
}

impl ManagedQualityWriter {
    pub fn run_id(&self) -> String {
        self.inner.store.snapshot().run_id
    }

    pub fn directory(&self) -> &Path {
        self.inner.store.directory()
    }

    pub fn snapshot(&self) -> QualityRunManifest {
        self.inner.store.snapshot()
    }

    pub fn accept(&self) -> Result<u64, ManagedQualityWriterError> {
        Ok(self.inner.store.accept()?)
    }

    pub fn candidate_dispatched(&self) -> Result<(), ManagedQualityWriterError> {
        Ok(self.inner.store.candidate_dispatched()?)
    }

    pub fn judge_dispatched(&self) -> Result<(), ManagedQualityWriterError> {
        Ok(self.inner.store.judge_dispatched()?)
    }

    pub fn unused_judge_credit(&self) -> Result<(), ManagedQualityWriterError> {
        Ok(self.inner.store.unused_judge_credit()?)
    }

    pub fn try_record(&self, outcome: QualityOutcome) -> Result<(), ManagedQualityWriterError> {
        let sequence = outcome.sequence;
        match self.inner.tx.try_send(Message::Outcome(Box::new(outcome))) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                let _ = self.inner.store.dropped(sequence);
                self.inner.store.set_writer_error();
                let _ = self.inner.store.flush();
                Err(ManagedQualityWriterError::QueueFull)
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let _ = self.inner.store.dropped(sequence);
                self.inner.store.set_writer_error();
                let _ = self.inner.store.flush();
                Err(ManagedQualityWriterError::Closed)
            }
        }
    }

    pub async fn shutdown(
        &self,
        cancelled: bool,
        grace: Duration,
    ) -> Result<QualityRunManifest, ManagedQualityWriterError> {
        let deadline = tokio::time::Instant::now() + grace;
        let (reply, receive) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.inner.tx.send(Message::Shutdown { cancelled, reply }),
        )
        .await
        .map_err(|_| ManagedQualityWriterError::ShutdownTimeout)?
        .map_err(|_| ManagedQualityWriterError::Closed)?;
        let manifest = tokio::time::timeout_at(deadline, receive)
            .await
            .map_err(|_| ManagedQualityWriterError::ShutdownTimeout)?
            .map_err(|_| ManagedQualityWriterError::Closed)?
            .map_err(ManagedQualityWriterError::Writer)?;
        let join = self
            .inner
            .join
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if let Some(join) = join {
            tokio::time::timeout_at(deadline, tokio::task::spawn_blocking(move || join.join()))
                .await
                .map_err(|_| ManagedQualityWriterError::ShutdownTimeout)?
                .map_err(|error| ManagedQualityWriterError::Writer(error.to_string()))?
                .map_err(|_| ManagedQualityWriterError::Writer("writer panicked".into()))?;
        }
        Ok(manifest)
    }
}

fn writer_thread(
    store: Arc<QualityRunStore>,
    mut ledger: bowline_core::quality_run::QualityLedger,
    mut rx: mpsc::Receiver<Message>,
    pause: Option<std::sync::mpsc::Receiver<()>>,
) {
    if let Some(wait) = pause {
        let _ = wait.recv();
    }
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            store.set_writer_error();
            let _ = store.finish(false);
            return;
        }
    };
    runtime.block_on(async move {
        let mut finished = false;
        while let Some(message) = rx.recv().await {
            match message {
                Message::Outcome(outcome) => {
                    if ledger.append(&outcome).is_err()
                        || store.recorded(outcome.sequence, outcome.status).is_err()
                    {
                        let _ = store.dropped(outcome.sequence);
                        store.set_writer_error();
                    }
                }
                Message::Shutdown { cancelled, reply } => {
                    rx.close();
                    while let Some(Message::Outcome(outcome)) = rx.recv().await {
                        if ledger.append(&outcome).is_err()
                            || store.recorded(outcome.sequence, outcome.status).is_err()
                        {
                            let _ = store.dropped(outcome.sequence);
                            store.set_writer_error();
                        }
                    }
                    let result = ledger
                        .flush()
                        .and_then(|()| store.flush())
                        .and_then(|()| store.finish(cancelled))
                        .map_err(|error| error.to_string());
                    finished = true;
                    let _ = reply.send(result);
                    break;
                }
            }
        }
        if !finished {
            store.set_writer_error();
            let _ = ledger.flush();
            let _ = store.finish(false);
        }
    });
}
