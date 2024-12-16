//! This module provides the [BrokerServer] which handles requests to interact with wireguard.
//! Specifically, it allows requests to set a pre-shared key for a wireguard interface.

use std::borrow::BorrowMut;

use rosenpass_secret_memory::{Public, Secret};

use crate::api::msgs::{self, Envelope, SetPskRequest, SetPskResponse};
use crate::WireGuardBroker;

use super::config::{NetworkBrokerConfigBuilder, NetworkBrokerConfigErr};

/// Error variants for the [BrokerServer].
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum BrokerServerError {
    /// Indicates that an unknown request type was encountered.
    #[error("No such request type: {}", .0)]
    NoSuchRequestType(u8),
    /// Indicates that an invalid message was sent.
    #[error("Invalid message received.")]
    InvalidMessage,
    /// Indicates an error when configuration the network broker.
    #[error("Network Broker Config error: {0}")]
    BrokerError(NetworkBrokerConfigErr),
}

impl From<msgs::InvalidMessageTypeError> for BrokerServerError {
    fn from(value: msgs::InvalidMessageTypeError) -> Self {
        let msgs::InvalidMessageTypeError = value; // Assert that this is a unit type
        BrokerServerError::InvalidMessage
    }
}

/// The broker server. It requires an inner [WireGuardBroker] and an error type such
/// that the [msgs::SetPskError] implements [From] for the error type.
/// # Type Parameters
/// - `Err`: The used error type. Must be chosen such that [msgs::SetPskError] implements
///   [From<Err>](From)
///- `Inner`: A [WireGuardBroker]-type parametrized with `Err`.
pub struct BrokerServer<Err, Inner>
where
    Inner: WireGuardBroker<Error = Err>,
    msgs::SetPskError: From<Err>,
{
    /// The inner [WireGuardBroker].
    inner: Inner,
}

impl<Err, Inner> BrokerServer<Err, Inner>
where
    Inner: WireGuardBroker<Error = Err>,
    msgs::SetPskError: From<Err>,
    Err: std::fmt::Debug,
{
    /// Creates a new [BrokerServer] from a [WireGuardBroker].
    pub fn new(inner: Inner) -> Self {
        Self { inner }
    }

    /// Processes a message (at the moment only setting the pre-shared key is supported)
    /// and takes the appropriate actions.
    ///
    /// # Errors
    /// - [BrokerServerError::InvalidMessage] if the message is not properly formatted or refers to
    ///   an unsupported message type.
    pub fn handle_message(
        &mut self,
        req: &[u8],
        res: &mut [u8; msgs::RESPONSE_MSG_BUFFER_SIZE],
    ) -> Result<usize, BrokerServerError> {
        use BrokerServerError::*;

        let typ = req.first().ok_or(InvalidMessage)?;
        let typ = msgs::MsgType::try_from(*typ)?;
        let msgs::MsgType::SetPsk = typ; // Assert type

        let req = zerocopy::Ref::<&[u8], Envelope<SetPskRequest>>::new(req)
            .ok_or(BrokerServerError::InvalidMessage)?;
        let mut res = zerocopy::Ref::<&mut [u8], Envelope<SetPskResponse>>::new(res)
            .ok_or(BrokerServerError::InvalidMessage)?;
        res.msg_type = msgs::MsgType::SetPsk as u8;
        self.handle_set_psk(&req.payload, &mut res.payload)?;

        Ok(res.bytes().len())
    }

    /// Sets the pre-shared key for the interface identified in `req` to the pre-shared key
    /// specified in `req`.
    ///
    /// # Errors
    /// - [InvalidMessage](BrokerServerError::InvalidMessage) if the `iface` specified in `req` is
    ///   longer than 255 bytes or not correctly encoded in utf8.
    fn handle_set_psk(
        &mut self,
        req: &SetPskRequest,
        res: &mut SetPskResponse,
    ) -> Result<(), BrokerServerError> {
        // Using unwrap here since lenses can not return fixed-size arrays.
        // TODO: Slices should give access to fixed size arrays
        let peer_id = Public::from_slice(&req.peer_id);
        let psk = Secret::from_slice(&req.psk);

        let interface = req
            .iface()
            .map_err(|_e| BrokerServerError::InvalidMessage)?;

        let config = NetworkBrokerConfigBuilder::default()
            .peer_id(&peer_id)
            .psk(&psk)
            .iface(interface)
            .build()
            .unwrap();
        let r: Result<(), Err> = self.inner.borrow_mut().set_psk(config.into());
        if let Err(e) = &r {
            eprintln!("Error setting PSK: {e:?}"); // TODO: Use rust log
        }

        let r: msgs::SetPskResult = r.map_err(|e| e.into());
        let r: msgs::SetPskResponseReturnCode = r.into();
        res.return_code = r as u8;

        Ok(())
    }
}
