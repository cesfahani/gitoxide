use gix_features::progress::Progress;
use gix_protocol::transport::client::Transport;

use crate::{
    bstr,
    bstr::BString,
    remote::{Connection, Direction},
};

/// The error returned by ['Connection::handshake()'].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum Error {
    #[error("Failed to configure the transport before connecting to {url:?}")]
    GatherTransportConfig {
        url: BString,
        source: crate::config::transport::Error,
    },
    #[error("Failed to configure the transport layer")]
    ConfigureTransport(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error(transparent)]
    Handshake(#[from] gix_protocol::handshake::Error),
    #[error("The object format {format:?} as used by the remote is unsupported")]
    UnknownObjectFormat { format: BString },
    #[error(transparent)]
    Transport(#[from] gix_protocol::transport::client::Error),
    #[error(transparent)]
    ConfigureCredentials(#[from] crate::config::credential_helpers::Error),
}

impl gix_protocol::transport::IsSpuriousError for Error {
    fn is_spurious(&self) -> bool {
        match self {
            Error::Transport(err) => err.is_spurious(),
            Error::Handshake(err) => err.is_spurious(),
            _ => false,
        }
    }
}

impl<'remote, 'repo, T> Connection<'remote, 'repo, T>
where
    T: Transport,
{
    ///
    #[gix_protocol::maybe_async::maybe_async]
    pub(crate) async fn handshake(
        &mut self,
        extra_parameters: Vec<(String, Option<String>)>,
        mut progress: impl Progress
    ) -> Result<gix_protocol::handshake::Outcome, Error> {
        let _span = gix_trace::coarse!("remote::Connection::handshake()");
        let mut credentials_storage;
        let url = self.transport.to_url();
        let authenticate = match self.authenticate.as_mut() {
            Some(f) => f,
            None => {
                let url = self.remote.url(Direction::Fetch).map_or_else(
                    || gix_url::parse(url.as_ref()).expect("valid URL to be provided by transport"),
                    ToOwned::to_owned,
                );
                credentials_storage = self.configured_credentials(url)?;
                &mut credentials_storage
            }
        };

        if self.transport_options.is_none() {
            self.transport_options = self
                .remote
                .repo
                .transport_options(url.as_ref(), self.remote.name().map(crate::remote::Name::as_bstr))
                .map_err(|err| Error::GatherTransportConfig {
                    source: err,
                    url: url.into_owned(),
                })?;
        }
        if let Some(config) = self.transport_options.as_ref() {
            self.transport.configure(&**config)?;
        }
        let outcome =
            gix_protocol::fetch::handshake(&mut self.transport, authenticate, extra_parameters, &mut progress).await?;
        Ok(outcome)
    }
}

/// Assume sha1 if server says nothing, otherwise configure anything beyond sha1 in the local repo configuration
#[allow(clippy::result_large_err)]
pub(crate) fn extract_object_format(
    _repo: &crate::Repository,
    outcome: &gix_protocol::handshake::Outcome,
) -> Result<gix_hash::Kind, Error> {
    use bstr::ByteSlice;
    let object_hash =
        if let Some(object_format) = outcome.capabilities.capability("object-format").and_then(|c| c.value()) {
            let object_format = object_format.to_str().map_err(|_| Error::UnknownObjectFormat {
                format: object_format.into(),
            })?;
            match object_format {
                "sha1" => gix_hash::Kind::Sha1,
                unknown => return Err(Error::UnknownObjectFormat { format: unknown.into() }),
            }
        } else {
            gix_hash::Kind::Sha1
        };
    Ok(object_hash)
}
