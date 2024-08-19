use std::{borrow::BorrowMut, collections::VecDeque, os::fd::OwnedFd};

use anyhow::Context;
use rosenpass_to::{ops::copy_slice, To};
use rosenpass_util::{
    fd::FdIo,
    functional::{run, ApplyExt},
    io::ReadExt,
    mem::DiscardResultExt,
    mio::UnixStreamExt,
    result::OkExt,
};
use rosenpass_wireguard_broker::brokers::mio_client::MioBrokerClient;

use crate::{
    api::{add_listen_socket_response_status, add_psk_broker_response_status},
    app_server::AppServer,
    protocol::BuildCryptoServer,
};

use super::{supply_keypair_response_status, Server as ApiServer};

#[derive(Debug)]
pub struct ApiHandler {
    _dummy: (),
}

impl ApiHandler {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self { _dummy: () }
    }
}

pub trait ApiHandlerContext {
    fn api_handler(&self) -> &ApiHandler;
    fn app_server(&self) -> &AppServer;
    fn api_handler_mut(&mut self) -> &mut ApiHandler;
    fn app_server_mut(&mut self) -> &mut AppServer;
}

#[derive(thiserror::Error, Debug)]
#[error("Error in SupplyKeypair")]
struct SupplyKeypairError {
    status: u128,
    #[source]
    cause: anyhow::Error,
}

trait SupplyKeypairErrorExt<T> {
    fn e_custom(self, status: u128) -> Result<T, SupplyKeypairError>;
    fn einternal(self) -> Result<T, SupplyKeypairError>;
    fn ealready_supplied(self) -> Result<T, SupplyKeypairError>;
    fn einvalid_req(self) -> Result<T, SupplyKeypairError>;
}

impl<T, E: Into<anyhow::Error>> SupplyKeypairErrorExt<T> for Result<T, E> {
    fn e_custom(self, status: u128) -> Result<T, SupplyKeypairError> {
        self.map_err(|e| SupplyKeypairError {
            status,
            cause: e.into(),
        })
    }

    fn einternal(self) -> Result<T, SupplyKeypairError> {
        self.e_custom(supply_keypair_response_status::INTERNAL_ERROR)
    }

    fn ealready_supplied(self) -> Result<T, SupplyKeypairError> {
        self.e_custom(supply_keypair_response_status::KEYPAIR_ALREADY_SUPPLIED)
    }

    fn einvalid_req(self) -> Result<T, SupplyKeypairError> {
        self.e_custom(supply_keypair_response_status::INVALID_REQUEST)
    }
}

impl<T> ApiServer for T
where
    T: ?Sized + ApiHandlerContext,
{
    fn ping(
        &mut self,
        req: &super::PingRequest,
        _req_fds: &mut VecDeque<OwnedFd>,
        res: &mut super::PingResponse,
    ) -> anyhow::Result<()> {
        let (req, res) = (&req.payload, &mut res.payload);
        copy_slice(&req.echo).to(&mut res.echo);
        Ok(())
    }

    fn supply_keypair(
        &mut self,
        req: &super::SupplyKeypairRequest,
        req_fds: &mut VecDeque<OwnedFd>,
        res: &mut super::SupplyKeypairResponse,
    ) -> anyhow::Result<()> {
        let outcome: Result<(), SupplyKeypairError> = run(|| {
            // Acquire the file descriptors
            let mut sk_io = FdIo(
                req_fds
                    .front()
                    .context("First file descriptor, secret key, missing.")
                    .einvalid_req()?,
            );
            let mut pk_io = FdIo(
                req_fds
                    .get(1)
                    .context("Second file descriptor, public key, missing.")
                    .einvalid_req()?,
            );

            // Actually read the secrets
            let mut sk = crate::protocol::SSk::zero();
            sk_io.read_exact_til_end(sk.secret_mut()).einvalid_req()?;

            let mut pk = crate::protocol::SPk::zero();
            pk_io.read_exact_til_end(pk.borrow_mut()).einvalid_req()?;

            // Retrieve the construction site
            let construction_site = self.app_server_mut().crypto_site.borrow_mut();

            // Retrieve the builder
            use rosenpass_util::build::ConstructionSite as C;
            let maybe_builder = match construction_site {
                C::Builder(builder) => Some(builder),
                C::Product(_) => None,
                C::Void => {
                    return Err(anyhow::Error::msg("CryptoServer construction side is void"))
                        .einternal();
                }
            };

            // Retrieve a reference to the keypair
            let Some(BuildCryptoServer {
                ref mut keypair, ..
            }) = maybe_builder
            else {
                return Err(anyhow::Error::msg("CryptoServer already built")).ealready_supplied();
            };

            // Supply the keypair to the CryptoServer
            keypair
                .insert(crate::protocol::Keypair { sk, pk })
                .discard_result();

            // Actually construct the CryptoServer
            construction_site
                .erect()
                .map_err(|e| anyhow::Error::msg(format!("Error erecting the CryptoServer {e:?}")))
                .einternal()?;

            Ok(())
        });

        // Handle errors
        use supply_keypair_response_status as status;
        let status = match outcome {
            Ok(()) => status::OK,
            Err(e) => {
                let lvl = match e.status {
                    status::INTERNAL_ERROR => log::Level::Warn,
                    _ => log::Level::Debug,
                };

                log::log!(
                    lvl,
                    "Error while processing API Request.\n    Request: {:?}\n    Error: {:?}",
                    req,
                    e.cause
                );

                if e.status == status::INTERNAL_ERROR {
                    return Err(e.cause);
                }

                e.status
            }
        };

        res.payload.status = status;

        Ok(())
    }

    fn add_listen_socket(
        &mut self,
        _req: &super::boilerplate::AddListenSocketRequest,
        req_fds: &mut VecDeque<OwnedFd>,
        res: &mut super::boilerplate::AddListenSocketResponse,
    ) -> anyhow::Result<()> {
        // Retrieve file descriptor
        let sock_res = run(|| -> anyhow::Result<mio::net::UdpSocket> {
            let sock = req_fds
                .pop_front()
                .context("Invalid request – socket missing.")?;
            // TODO: We need to have this outside linux
            #[cfg(target_os = "linux")]
            rosenpass_util::fd::GetSocketProtocol::demand_udp_socket(&sock)?;
            let sock = std::net::UdpSocket::from(sock);
            sock.set_nonblocking(true)?;
            mio::net::UdpSocket::from_std(sock).ok()
        });

        let sock = match sock_res {
            Ok(sock) => sock,
            Err(e) => {
                log::debug!("Error processing AddListenSocket API request: {e:?}");
                res.payload.status = add_listen_socket_response_status::INVALID_REQUEST;
                return Ok(());
            }
        };

        // Register socket
        let reg_result = self.app_server_mut().register_listen_socket(sock);

        if let Err(internal_error) = reg_result {
            log::warn!("Internal error processing AddListenSocket API request: {internal_error:?}");
            res.payload.status = add_listen_socket_response_status::INTERNAL_ERROR;
            return Ok(());
        };

        res.payload.status = add_listen_socket_response_status::OK;
        Ok(())
    }

    fn add_psk_broker(
        &mut self,
        _req: &super::boilerplate::AddPskBrokerRequest,
        req_fds: &mut VecDeque<OwnedFd>,
        res: &mut super::boilerplate::AddPskBrokerResponse,
    ) -> anyhow::Result<()> {
        // Retrieve file descriptor
        let sock_res = run(|| {
            let sock = req_fds
                .pop_front()
                .context("Invalid request – socket missing.")?;
            mio::net::UnixStream::from_fd(sock)
        });

        // Handle errors
        let sock = match sock_res {
            Ok(sock) => sock,
            Err(e) => {
                log::debug!(
                    "Request found to be invalid while processing AddPskBroker API request: {e:?}"
                );
                res.payload.status = add_psk_broker_response_status::INVALID_REQUEST;
                return Ok(());
            }
        };

        // Register Socket
        let client = Box::new(MioBrokerClient::new(sock));

        // Workaround: The broker code is currently impressively overcomplicated. Brokers are
        // stored in a hash map but the hash map key used is just a counter so a vector could
        // have been used. Broker configuration is abstracted, different peers can have different
        // brokers but there is no facility to add multiple brokers in practice. The broker index
        // uses a `Public` wrapper without actually holding any cryptographic data. Even the broker
        // configuration uses a trait abstraction for no discernible reason and a lot of the code
        // introduces pointless, single-field wrapper structs.
        // We should use an implement-what-is-actually-needed strategy next time.
        // The Broker code needs to be slimmed down, the right direction to go is probably to
        // just add event and capability support to the API and use the API to deliver OSK events.
        //
        // For now, we just replace the latest broker.
        let erase_ptr = {
            use crate::app_server::BrokerStorePtr;
            //
            use rosenpass_secret_memory::Public;
            use zerocopy::AsBytes;
            (self.app_server().brokers.store.len() - 1)
                .apply(|x| x as u64)
                .apply(|x| Public::from_slice(x.as_bytes()))
                .apply(BrokerStorePtr)
        };

        let register_result = run(|| {
            let srv = self.app_server_mut();
            srv.unregister_broker(erase_ptr)?;
            srv.register_broker(client)
        });

        if let Err(e) = register_result {
            log::warn!("Internal error while processing AddPskBroker API request: {e:?}");
            res.payload.status = add_psk_broker_response_status::INTERNAL_ERROR;
            return Ok(());
        }

        res.payload.status = add_psk_broker_response_status::OK;
        Ok(())
    }
}
