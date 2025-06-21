use rand::Rng;

pub mod an23_proxy_signature;

#[derive(Debug)]
pub enum Error {
    SetupFailed,
    InvalidSignature,
    InvalidToken,
    DelegationFailed,
}

pub trait ProxySignature {
    type Parameters;
    type SigningKey;
    type VerificationKey;
    type Policy;
    type DelegationSpec;
    type DelegationInfo;
    type RevocationKey;
    type RevocationState;
    type Signature;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error>;

    fn keygen<R: Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
    ) -> Result<(Self::SigningKey, Self::VerificationKey), Error>;

    fn sign<R: Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
        sk: &Self::SigningKey,
        message: &[u8],
        policy: Option<&Self::Policy>,
    ) -> Result<Self::Signature, Error>;

    fn delegate<R: Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
        sk: &Self::SigningKey,
        deg_spec: &Self::DelegationSpec,
    ) -> Result<(Self::DelegationInfo, Self::RevocationKey), Error>;

    fn delegated_sign<R: Rng>(
        rng: &mut R,
        parameters: &Self::Parameters,
        delegation_info: &Self::DelegationInfo,
        message: &[u8],
    ) -> Result<Self::Signature, Error>;

    fn revoke(
        parameters: &Self::Parameters,
        delegation_info: &Self::DelegationInfo,
        rev_key: &Self::RevocationKey,
    ) -> Result<Self::RevocationState, Error>;

    fn verify(
        parameters: &Self::Parameters,
        vk: &Self::VerificationKey,
        message: &[u8],
        signature: &Self::Signature,
        rev_state: &mut Self::RevocationState,
    ) -> Result<bool, Error>;
}
