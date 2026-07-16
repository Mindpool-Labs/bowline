pub trait ServingLease: Send {
    fn try_acquire(&mut self) -> anyhow::Result<bool>;

    fn may_admit(&self) -> bool;

    fn release(&mut self) -> anyhow::Result<()>;
}

#[derive(Debug, Default)]
pub struct LocalServingLease;

impl ServingLease for LocalServingLease {
    fn try_acquire(&mut self) -> anyhow::Result<bool> {
        Ok(true)
    }

    fn may_admit(&self) -> bool {
        true
    }

    fn release(&mut self) -> anyhow::Result<()> {
        Ok(())
    }
}
