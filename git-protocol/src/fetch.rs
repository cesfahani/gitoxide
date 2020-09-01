use crate::credentials;
use bstr::{BStr, BString, ByteSlice};
use git_object::owned;
use git_transport::{
    client::{self, SetServiceResponse},
    Service,
};
use quick_error::quick_error;
use std::{collections::BTreeMap, io};

quick_error! {
    #[derive(Debug)]
    pub enum Error {
        Credentials(err: credentials::Error) {
            display("Failed to obtain, approve or reject credentials")
            from()
            source(err)
        }
        Transport(err: client::Error) {
            display("An error occurred on the transport layer while fetching data")
            from()
            source(err)
        }
    }
}

pub trait Delegate {
    /// A chance to inspect or adjust the Capabilities returned after handshake with the server.
    /// They will be used in subsequent calls to the server, but the client is free to cache information as they see fit.
    fn adjust_capabilities(&mut self, _version: git_transport::Protocol, _capabilities: &mut Capabilities) {}
}

pub struct Capabilities {
    pub available: BTreeMap<BString, Option<BString>>,
}

impl Capabilities {
    /// Returns values of capability of the given name, if present.
    /// Useful when handling capabilities of V2 commands.
    pub fn values_of(&self, name: &str) -> Option<impl Iterator<Item = &BStr>> {
        self.available
            .get(name.as_bytes().as_bstr())
            .and_then(|v| v.as_ref().map(|v| v.split(|b| *b == b' ').map(|v| v.as_bstr())))
    }

    pub(crate) fn set_agent_version(&mut self) {
        self.available.insert(
            "agent".into(),
            Some(concat!("git/oxide-", env!("CARGO_PKG_VERSION")).into()),
        );
    }
}

impl From<client::Capabilities> for Capabilities {
    fn from(c: client::Capabilities) -> Self {
        Capabilities {
            available: {
                let mut map = BTreeMap::new();
                map.extend(c.iter().map(|c| (c.name().to_owned(), c.value().map(|v| v.to_owned()))));
                map
            },
        }
    }
}

// ("multi_ack", None),
// ("thin-pack", None),
// ("side-band", None),
// ("side-band-64k", None),
// ("ofs-delta", None),
// ("shallow", None),
// ("deepen-since", None),
// ("deepen-not", None),
// ("deepen-relative", None),
// ("no-progress", None),
// ("include-tag", None),
// ("multi_ack_detailed", None),
// ("allow-tip-sha1-in-want", None),
// ("allow-reachable-sha1-in-want", None),
// ("no-done", None),
// ("symref", Some("HEAD:refs/heads/main")),
// ("filter", None),
// ("agent", Some("git/github-gdf51a71f0236"))
//

// V1
// 0098want 808e50d724f604f69ab93c6da2919c014667bedb multi_ack_detailed no-done side-band-64k thin-pack ofs-delta deepen-since deepen-not agent=git/2.28.0

/// This types sole purpose is to 'disable' the destructor on the Box provided in the `SetServiceResponse` type
/// by leaking the box. We provide a method to restore the box and drop it right away to not actually leak.
/// However, we do leak in error cases because we don't call the manual destructor then.
struct LeakedSetServiceResponse<'a> {
    /// The protocol the service can provide. May be different from the requested one
    pub actual_protocol: git_transport::Protocol,
    pub capabilities: client::Capabilities,
    /// In protocol version one, this is set to a list of refs and their peeled counterparts.
    pub refs: Option<&'a mut dyn io::BufRead>,
}

impl<'a> From<client::SetServiceResponse<'a>> for LeakedSetServiceResponse<'a> {
    fn from(v: SetServiceResponse<'a>) -> Self {
        LeakedSetServiceResponse {
            actual_protocol: v.actual_protocol,
            capabilities: v.capabilities,
            refs: v.refs.map(Box::leak),
        }
    }
}

impl<'a> From<LeakedSetServiceResponse<'a>> for client::SetServiceResponse<'a> {
    fn from(v: LeakedSetServiceResponse<'a>) -> Self {
        SetServiceResponse {
            actual_protocol: v.actual_protocol,
            capabilities: v.capabilities,
            refs: v.refs.map(|b| {
                // SAFETY: We are bound to lifetime 'a, which is the lifetime of the thing pointed to by the trait object in the box.
                // Thus we can only drop the box while that thing is indeed valid, due to Rusts standard lifetime rules.
                // The box itself was leaked by us.
                // Note that this is only required because Drop scopes are the outer ones in the match, not the match arms, making them
                // too broad to be usable intuitively. I consider this a technical shortcoming and hope there is a way to resolve it.
                #[allow(unsafe_code)]
                unsafe {
                    Box::from_raw(b as *mut _)
                }
            }),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Hash, Ord, PartialOrd, Clone)]
#[cfg_attr(feature = "serde1", derive(serde::Serialize, serde::Deserialize))]
pub enum Ref {
    Tag {
        path: BString,
        id: owned::Id,
    },
    Commit {
        path: BString,
        id: owned::Id,
    },
    Symbolic {
        path: BString,
        target: BString,
        id: owned::Id,
    },
    /// extracted from V1 capabilities, which contain some important symbolic refs along with their targets
    /// These don't contain the Id
    SymbolicForLookup {
        path: BString,
        target: BString,
    },
}

fn extract_symrefs(out_refs: &mut Vec<Ref>, capabilities: &mut Capabilities) {
    // capabilities.available.iter()
}

pub fn fetch<F: FnMut(credentials::Action) -> credentials::Result>(
    mut transport: impl client::Transport,
    mut delegate: impl Delegate,
    mut authenticate: F,
) -> Result<(), Error> {
    let SetServiceResponse {
        actual_protocol,
        capabilities,
        refs,
    } = match transport
        .handshake(Service::UploadPack)
        .map(LeakedSetServiceResponse::from)
    {
        Ok(v) => Ok(v),
        Err(client::Error::Io { err }) if err.kind() == io::ErrorKind::PermissionDenied => {
            let url = transport.to_url();
            let credentials::Outcome { identity, next } = authenticate(credentials::Action::Fill(&url))?;
            transport.set_identity(identity)?;
            match transport
                .handshake(Service::UploadPack)
                .map(LeakedSetServiceResponse::from)
            {
                Ok(v) => {
                    authenticate(next.approve())?;
                    Ok(v)
                }
                // Still no permission? Reject the credentials.
                Err(client::Error::Io { err }) if err.kind() == io::ErrorKind::PermissionDenied => {
                    authenticate(next.reject())?;
                    Err(client::Error::Io { err })
                }
                // Otherwise, do nothing, as we don't know if it actually got to try the credentials.
                // If they were previously stored, they remain. In the worst case, the user has to enter them again
                // next time they try.
                Err(err) => Err(err),
            }
        }
        Err(err) => Err(err),
    }?
    .into();

    let mut capabilities: Capabilities = capabilities.into();
    delegate.adjust_capabilities(actual_protocol, &mut capabilities);
    capabilities.set_agent_version();
    let mut parsed_refs = Vec::<Ref>::new();
    extract_symrefs(&mut parsed_refs, &mut capabilities);

    match refs {
        Some(refs) => {
            assert_eq!(
                actual_protocol,
                git_transport::Protocol::V1,
                "Only V1 auto-responds with refs"
            );
            use io::BufRead;
            let refs = refs.lines().collect::<Vec<_>>();
        }
        None => {
            assert_eq!(
                actual_protocol,
                git_transport::Protocol::V2,
                "Only V2 needs a separate request to get specific refs"
            );
        }
    };

    unimplemented!("rest of fetch")
}

#[cfg(test)]
mod tests {
    use super::{extract_symrefs, Capabilities};
    use std::collections::BTreeMap;

    #[test]
    fn extract_symbolic_references_from_capabilities() {
        let mut caps = Capabilities {
            available: {
                let mut m = BTreeMap::new();
                m.insert("unrelated".into(), None);
                m.insert("symref".into(), Some("HEAD:refs/heads/main".into()));
                m.insert("symref".into(), Some("ANOTHER:refs/heads/baz".into()));
                m.insert("also-unrelated".into(), Some("with-value".into()));
                m
            },
        };
        let mut out = Vec::new();
        extract_symrefs(&mut out, &mut caps);

        assert_eq!(
            caps.available.into_iter().collect::<Vec<_>>(),
            vec![
                ("unrelated".into(), None),
                ("unrelated".into(), Some("with-value".into()))
            ]
        )
    }
}
