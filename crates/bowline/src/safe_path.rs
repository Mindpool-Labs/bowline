use std::{ffi::OsString, path::Component, path::Path};

use anyhow::Result;

pub(crate) fn anchored_components(path: &Path, label: &str) -> Result<Vec<OsString>> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    absolute
        .components()
        .filter_map(|component| match component {
            Component::Normal(name) => Some(Ok(name.to_owned())),
            Component::RootDir | Component::CurDir => None,
            Component::ParentDir | Component::Prefix(_) => {
                Some(Err(anyhow::anyhow!("unsafe {label} path component")))
            }
        })
        .collect()
}
