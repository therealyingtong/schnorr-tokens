use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::Rng;

pub mod an23_proxy_signature;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    SetupFailed,
    InvalidSignature,
    InvalidToken,
    DelegationFailed,
    UseOfRevokedToken,
    NoDelegationToken
}

/// Interface for a proxy signature scheme as defined in [AN23](https://eprint.iacr.org/2023/833).
pub trait ProxySignature {
    /// Public parameters,
    type Parameters: CanonicalSerialize + CanonicalDeserialize;
    /// Private signing key.
    type SigningKey;
    /// Public verification key.
    type VerificationKey: CanonicalSerialize + CanonicalDeserialize;
    /// The type of messages that can be signed.
    type Message;
    /// The type of policy that can be used to restrict the delegation.
    type Policy;
    /// Auxiliary information about the delegation. For example: the number of authorized proxy signatures, the time period during which the delegation is valid (if using timelock encryption), etc.
    type DelegationSpec;
    /// Delegation information used by a proxy to sign messages on behalf of the delegator. Anyone with this information can sign messages on behalf of the delegator; treat with care!
    type DelegationInfo;
    /// Revocation keys.
    type RevocationKey;
    /// A publicly accessible, append-only list of revoked delegation information.
    type RevocationState;
    /// A signature.
    type Signature: CanonicalSerialize + CanonicalDeserialize;

    /// Generates the public parameters for the proxy signature scheme.
    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    /// Generate a signing and verifying key pair.
    fn keygen<R: Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
    ) -> Result<(Self::SigningKey, Self::VerificationKey), Error>;

    /// Sign using the signing key.
    fn sign<R: Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
        sk: &Self::SigningKey,
        message: &Self::Message,
        policy: Option<&Self::Policy>,
    ) -> Result<Self::Signature, Error>;

    /// Generate delegation information for the proxy and a revocation key to be kept by the delegator.
    fn delegate<R: Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
        sk: &Self::SigningKey,
        deg_spec: &Self::DelegationSpec,
    ) -> Result<(Self::DelegationInfo, Self::RevocationKey), Error>;

    /// The proxy signer can use the delegation information to sign messages on behalf of the delegator. The delegation info gets updated to remove any information that cannot be re-used.
    fn delegated_sign<R: Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
        delegation_info: &mut Self::DelegationInfo,
        message: &Self::Message,
    ) -> Result<Self::Signature, Error>;

    /// The delegator can revoke the delegation by providing the revocation key and updating the revocation state.
    fn revoke(
        parameters: &Self::Parameters,
        delegation_info: &Self::DelegationInfo,
        rev_key: &Self::RevocationKey,
        rev_state: &mut Self::RevocationState,
    ) -> Result<(), Error>;

    /// Verify the signature against the message and the verification key; update the revocation state if verification succeeds.
    fn verify(
        parameters: &Self::Parameters,
        vk: &Self::VerificationKey,
        message: &Self::Message,
        signature: &Self::Signature,
        rev_state: &mut Self::RevocationState,
    ) -> Result<bool, Error>;
}
