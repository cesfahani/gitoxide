use std::collections::HashSet;

use gix_features::progress::Progress;
use gix_protocol::transport::client::Transport;

use crate::{
    bstr::{BString, ByteVec},
    remote::{connection, connection::HandshakeWithRefs, fetch, fetch::SpecIndex, Connection},
};

/// The error returned by [`Connection::ref_map()`].
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
    Handshake(#[from] connection::handshake::Error),
    #[error(transparent)]
    ListRefs(#[from] gix_protocol::ls_refs::Error),
    #[error(transparent)]
    Transport(#[from] gix_protocol::transport::client::Error),
    #[error(transparent)]
    ConfigureCredentials(#[from] crate::config::credential_helpers::Error),
    #[error(transparent)]
    MappingValidation(#[from] gix_refspec::match_group::validate::Error),
}

impl gix_protocol::transport::IsSpuriousError for Error {
    fn is_spurious(&self) -> bool {
        match self {
            Error::Transport(err) => err.is_spurious(),
            Error::ListRefs(err) => err.is_spurious(),
            Error::Handshake(err) => err.is_spurious(),
            _ => false,
        }
    }
}

/// For use in [`Connection::ref_map()`].
#[derive(Debug, Clone)]
pub struct Options {
    /// Use a two-component prefix derived from the ref-spec's source, like `refs/heads/`  to let the server pre-filter refs
    /// with great potential for savings in traffic and local CPU time. Defaults to `true`.
    pub prefix_from_spec_as_filter_on_remote: bool,
    /// Parameters in the form of `(name, optional value)` to add to the handshake.
    ///
    /// This is useful in case of custom servers.
    pub handshake_parameters: Vec<(String, Option<String>)>,
    /// A list of refspecs to use as implicit refspecs which won't be saved or otherwise be part of the remote in question.
    ///
    /// This is useful for handling `remote.<name>.tagOpt` for example.
    pub extra_refspecs: Vec<gix_refspec::RefSpec>,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            prefix_from_spec_as_filter_on_remote: true,
            handshake_parameters: Vec::new(),
            extra_refspecs: Vec::new(),
        }
    }
}

impl<'remote, 'repo, T> Connection<'remote, 'repo, T>
where
    T: Transport,
{
    /// List all references on the remote that have been filtered through our remote's [`refspecs`][crate::Remote::refspecs()]
    /// for _fetching_.
    ///
    /// This comes in the form of all matching tips on the remote and the object they point to, along with
    /// with the local tracking branch of these tips (if available).
    ///
    /// Note that this doesn't fetch the objects mentioned in the tips nor does it make any change to underlying repository.
    ///
    /// # Consumption
    ///
    /// Due to management of the transport, it's cleanest to only use it for a single interaction. Thus it's consumed along with
    /// the connection.
    ///
    /// ### Configuration
    ///
    /// - `gitoxide.userAgent` is read to obtain the application user agent for git servers and for HTTP servers as well.
    #[allow(clippy::result_large_err)]
    #[gix_protocol::maybe_async::maybe_async]
    pub async fn ref_map(mut self, progress: impl Progress, options: Options) -> Result<fetch::RefMap, Error> {
        let res = self.ref_map_inner(progress, options).await;
        gix_protocol::indicate_end_of_interaction(&mut self.transport, self.trace)
            .await
            .ok();
        res
    }

    #[allow(clippy::result_large_err)]
    #[gix_protocol::maybe_async::maybe_async]
    pub(crate) async fn ref_map_inner(
        &mut self,
        progress: impl Progress,
        Options {
            prefix_from_spec_as_filter_on_remote,
            handshake_parameters,
            mut extra_refspecs,
        }: Options,
    ) -> Result<fetch::RefMap, Error> {
        let _span = gix_trace::coarse!("remote::Connection::ref_map()");
        let null = gix_hash::ObjectId::null(gix_hash::Kind::Sha1); // OK to hardcode Sha1, it's not supposed to match, ever.

        if let Some(tag_spec) = self.remote.fetch_tags.to_refspec().map(|spec| spec.to_owned()) {
            if !extra_refspecs.contains(&tag_spec) {
                extra_refspecs.push(tag_spec);
            }
        };
        let specs = {
            let mut s = self.remote.fetch_specs.clone();
            s.extend(extra_refspecs.clone());
            s
        };
        let remote = self
            .fetch_refs(
                prefix_from_spec_as_filter_on_remote,
                handshake_parameters,
                &specs,
                progress,
            )
            .await?;
        let num_explicit_specs = self.remote.fetch_specs.len();
        let group = gix_refspec::MatchGroup::from_fetch_specs(specs.iter().map(gix_refspec::RefSpec::to_ref));
        let (res, fixes) = group
            .match_remotes(remote.refs.iter().map(|r| {
                let (full_ref_name, target, object) = r.unpack();
                gix_refspec::match_group::Item {
                    full_ref_name,
                    target: target.unwrap_or(&null),
                    object,
                }
            }))
            .validated()?;
        let mappings = res.mappings;
        let mappings = mappings
            .into_iter()
            .map(|m| fetch::Mapping {
                remote: m.item_index.map_or_else(
                    || {
                        fetch::Source::ObjectId(match m.lhs {
                            gix_refspec::match_group::SourceRef::ObjectId(id) => id,
                            _ => unreachable!("no item index implies having an object id"),
                        })
                    },
                    |idx| fetch::Source::Ref(remote.refs[idx].clone()),
                ),
                local: m.rhs.map(std::borrow::Cow::into_owned),
                spec_index: if m.spec_index < num_explicit_specs {
                    SpecIndex::ExplicitInRemote(m.spec_index)
                } else {
                    SpecIndex::Implicit(m.spec_index - num_explicit_specs)
                },
            })
            .collect();

        let object_hash = connection::handshake::extract_object_format(self.remote.repo, &remote.outcome)?;
        Ok(fetch::RefMap {
            mappings,
            extra_refspecs,
            fixes,
            remote_refs: remote.refs,
            handshake: remote.outcome,
            object_hash,
        })
    }

    #[allow(clippy::result_large_err)]
    #[gix_protocol::maybe_async::maybe_async]
    async fn fetch_refs(
        &mut self,
        filter_by_prefix: bool,
        extra_parameters: Vec<(String, Option<String>)>,
        refspecs: &[gix_refspec::RefSpec],
        mut progress: impl Progress,
    ) -> Result<HandshakeWithRefs, Error> {
        let _span = gix_trace::coarse!("remote::Connection::fetch_refs()");
        let mut outcome =
            self.handshake(extra_parameters, &mut progress).await?;
        let refs = match outcome.refs.take() {
            Some(refs) => refs,
            None => {
                let agent_feature = self.remote.repo.config.user_agent_tuple();
                gix_protocol::ls_refs(
                    &mut self.transport,
                    &outcome.capabilities,
                    move |_capabilities, arguments, features| {
                        features.push(agent_feature);
                        if filter_by_prefix {
                            let mut seen = HashSet::new();
                            for spec in refspecs {
                                let spec = spec.to_ref();
                                if seen.insert(spec.instruction()) {
                                    let mut prefixes = Vec::with_capacity(1);
                                    spec.expand_prefixes(&mut prefixes);
                                    for mut prefix in prefixes {
                                        prefix.insert_str(0, "ref-prefix ");
                                        arguments.push(prefix);
                                    }
                                }
                            }
                        }
                        Ok(gix_protocol::ls_refs::Action::Continue)
                    },
                    &mut progress,
                    self.trace,
                )
                .await?
            }
        };
        Ok(HandshakeWithRefs { outcome, refs })
    }
}
