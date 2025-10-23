use tokio_stream::{self as stream, StreamExt};
use dav_server::{
	davpath::DavPath, fs::{DavDirEntry, DavFile, DavMetaData, FsFuture, FsResult, FsStream, GuardedFileSystem, OpenOptions, ReadDirMeta}, localfs::LocalFs
};

use std::{fmt::Display, path::Path};
use hyper::{body::Incoming, Request};

#[derive(Clone)]
pub struct Filter;

impl Filter {
	// @todo: Implement proper Auth flow
	pub async fn from_request(request: &Request<Incoming>) -> Result<Self, Box<dyn Display>> {
		let _auth = request.headers()
			.get("Authorization")
			.ok_or(Box::new("Missing Authorization header") as Box<dyn Display>)?;

		Ok(Self)
	}

	pub async fn matches(&self, entry: &dyn DavDirEntry) -> FsResult<bool> {
		Ok(entry.is_dir().await? == true)
	}
}

// @todo: Remove reliance on LocalFs
#[derive(Clone)]
pub struct SurrealFS {
	inner: Box<LocalFs>
}

impl SurrealFS {
	pub fn new(dir: impl AsRef<Path>) -> Self {
		Self {
			inner: LocalFs::new(dir, false, false, false)
		}
	}
}

impl GuardedFileSystem<Filter> for SurrealFS {
	fn open<'a>(&'a self, path: &'a DavPath, options: OpenOptions, _credentials: &'a Filter) -> FsFuture<'a, Box<dyn DavFile>> {
		self.inner.open(path, options, &())
	}

	fn read_dir<'a>(
        &'a self,
        path: &'a DavPath,
        meta: ReadDirMeta,
        filter: &'a Filter,
    ) -> FsFuture<'a, FsStream<Box<dyn DavDirEntry>>> {
    	Box::pin(async move {
     		let mut stream = self.inner.read_dir(path, meta, &()).await?;
       		let mut entries = Vec::default();
        	while let Some(entry) = stream.next().await {
			let entry = entry?;
				if filter.matches(entry.as_ref()).await? {
					entries.push(Ok(entry));
				}
			}
			Ok(Box::pin(stream::iter(entries)) as _)
     	})
    }

	fn metadata<'a>(
        &'a self,
        path: &'a DavPath,
        _credentials: &'a Filter,
    ) -> FsFuture<'a, Box<dyn DavMetaData>> {
    	self.inner.metadata(path, &())
    }
}
