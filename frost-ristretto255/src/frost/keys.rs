//! FROST keys, keygen, key shares

use std::{collections::HashMap, convert::TryFrom, fmt::Debug};

use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT, ristretto::RistrettoPoint, scalar::Scalar,
    traits::Identity,
};
use hex::FromHex;
use rand_core::{CryptoRng, RngCore};
use zeroize::DefaultIsZeroes;

use crate::VerificationKey;

/// A secret scalar value representing a single signer's secret key.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Secret(pub(super) Scalar);

impl Secret {
    /// Generates a new uniformly random secret value using the provided RNG.
    pub fn random<R>(rng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        Self(Scalar::random(rng))
    }
}

// Zeroizes `Secret` to be the `Default` value on drop (when it goes out of scope).  Luckily the
// derived `Default` includes the `Default` impl of Scalar, which is four 0u64's under the hood.
impl DefaultIsZeroes for Secret {}

impl From<Scalar> for Secret {
    fn from(source: Scalar) -> Secret {
        Secret(source)
    }
}

impl FromHex for Secret {
    type Error = &'static str;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let mut bytes = [0u8; 32];

        match hex::decode_to_slice(hex, &mut bytes[..]) {
            Ok(()) => Secret::try_from(bytes),
            Err(_) => Err("invalid hex"),
        }
    }
}

impl TryFrom<[u8; 32]> for Secret {
    type Error = &'static str;

    fn try_from(source: [u8; 32]) -> Result<Self, &'static str> {
        match Scalar::from_canonical_bytes(source) {
            Some(scalar) => Ok(Secret(scalar)),
            None => Err("scalar was not canonically encoded"),
        }
    }
}

/// A public group element that represents a single signer's public key.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Public(pub(super) RistrettoPoint);

impl From<RistrettoPoint> for Public {
    fn from(source: RistrettoPoint) -> Public {
        Public(source)
    }
}

impl From<Secret> for Public {
    fn from(secret: Secret) -> Public {
        Public(RISTRETTO_BASEPOINT_POINT * secret.0)
    }
}

/// A Ristretto point that is a commitment to one coefficient of our secret
/// polynomial.
///
/// This is a (public) commitment to one coefficient of a secret polynomial used
/// for performing verifiable secret sharing for a Shamir secret share.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) struct CoefficientCommitment(pub(super) RistrettoPoint);

/// Contains the commitments to the coefficients for our secret polynomial _f_,
/// used to generate participants' key shares.
///
/// [`VerifiableSecretSharingCommitment`] contains a set of commitments to the coefficients (which
/// themselves are scalars) for a secret polynomial f, where f is used to
/// generate each ith participant's key share f(i). Participants use this set of
/// commitments to perform verifiable secret sharing.
///
/// Note that participants MUST be assured that they have the *same*
/// [`VerifiableSecretSharingCommitment`], either by performing pairwise comparison, or by using
/// some agreed-upon public location for publication, where each participant can
/// ensure that they received the correct (and same) value.
#[derive(Clone)]
pub struct VerifiableSecretSharingCommitment(pub(super) Vec<CoefficientCommitment>);

/// A secret share generated by performing a (t-out-of-n) secret sharing scheme.
///
/// `n` is the total number of shares and `t` is the threshold required to reconstruct the secret;
/// in this case we use Shamir's secret sharing.
#[derive(Clone)]
pub struct SecretShare {
    pub(super) index: u16,
    /// Secret Key.
    pub(super) value: Secret,
    /// The commitments to be distributed among signers.
    pub(super) commitment: VerifiableSecretSharingCommitment,
}

impl SecretShare {
    /// Verifies that a share is consistent with a commitment.
    ///
    /// This ensures that this participant's share has been generated using the same
    /// mechanism as all other signing participants. Note that participants *MUST*
    /// ensure that they have the same view as all other participants of the
    /// commitment!
    pub fn verify(&self) -> Result<(), &'static str> {
        let f_result = RISTRETTO_BASEPOINT_POINT * self.value.0;

        let x = Scalar::from(self.index as u16);

        let (_, result) = self.commitment.0.iter().fold(
            (Scalar::one(), RistrettoPoint::identity()),
            |(x_to_the_i, sum_so_far), comm_i| (x_to_the_i * x, sum_so_far + comm_i.0 * x_to_the_i),
        );

        if !(f_result == result) {
            return Err("SecretShare is invalid.");
        }

        Ok(())
    }
}

/// A Ristretto point that is a commitment to one coefficient of our secret
/// polynomial.
///
/// This is a (public) commitment to one coefficient of a secret polynomial used
/// for performing verifiable secret sharing for a Shamir secret share.
#[derive(Clone, Copy, Debug, PartialEq)]
// TODO: deprecate
pub(super) struct Commitment(pub(super) RistrettoPoint);

/// Secret and public key material generated by a dealer performing
/// [`keygen_with_dealer`].
///
/// To derive a FROST keypair, the receiver of the [`SharePackage`] *must* call
/// .into(), which under the hood also performs validation.
#[derive(Clone)]
pub struct SharePackage {
    /// Denotes the participant index each share is owned by.
    pub index: u16,
    /// This participant's secret share.
    pub(super) secret_share: SecretShare,
    /// This participant's public key.
    pub public: Public,
    /// The public signing key that represents the entire group.
    pub group_public: VerificationKey,
}

/// Allows all participants' keys to be generated using a central, trusted
/// dealer.
///
/// Under the hood, this performs verifiable secret sharing, which itself uses
/// Shamir secret sharing, from which each share becomes a participant's secret
/// key. The output from this function is a set of shares along with one single
/// commitment that participants use to verify the integrity of the share. The
/// number of signers is limited to 255.
///
/// Implements [`trusted_dealer_keygen`] from the spec.
///
/// [`trusted_dealer_keygen`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#appendix-B
pub fn keygen_with_dealer<R: RngCore + CryptoRng>(
    num_signers: u8,
    threshold: u8,
    mut rng: R,
) -> Result<(Vec<SharePackage>, PublicKeyPackage), &'static str> {
    let mut bytes = [0; 64];
    rng.fill_bytes(&mut bytes);

    let secret = Secret::random(&mut rng);
    let group_public = VerificationKey::from(&secret.0);
    let secret_shares = generate_secret_shares(&secret, num_signers, threshold, rng)?;
    let mut share_packages: Vec<SharePackage> = Vec::with_capacity(num_signers as usize);
    let mut signer_pubkeys: HashMap<u16, Public> = HashMap::with_capacity(num_signers as usize);

    for secret_share in secret_shares {
        let signer_public = secret_share.value.into();

        share_packages.push(SharePackage {
            index: secret_share.index,
            secret_share: secret_share.clone(),
            public: signer_public,
            group_public,
        });

        signer_pubkeys.insert(secret_share.index, signer_public);
    }

    Ok((
        share_packages,
        PublicKeyPackage {
            signer_pubkeys,
            group_public,
        },
    ))
}

/// A FROST keypair, which can be generated either by a trusted dealer or using
/// a DKG.
///
/// When using a central dealer, [`SharePackage`]s are distributed to
/// participants, who then perform verification, before deriving
/// [`KeyPackage`]s, which they store to later use during signing.
#[derive(Copy, Clone, Debug)]
pub struct KeyPackage {
    /// Denotes the participant index each secret share key package is owned by.
    pub index: u16,
    /// This participant's secret share.
    pub(super) secret_share: Secret,
    /// This participant's public key.
    pub public: Public,
    /// The public signing key that represents the entire group.
    pub group_public: VerificationKey,
}

impl TryFrom<SharePackage> for KeyPackage {
    type Error = &'static str;

    /// Tries to verify a share and construct a [`KeyPackage`] from it.
    ///
    /// When participants receive a [`SharePackage`] from the dealer, they
    /// *MUST* verify the integrity of the share before continuing on to
    /// transform it into a signing/verification keypair. Here, we assume that
    /// every participant has the same view of the commitment issued by the
    /// dealer, but implementations *MUST* make sure that all participants have
    /// a consistent view of this commitment in practice.
    fn try_from(share_package: SharePackage) -> Result<Self, &'static str> {
        share_package.secret_share.verify()?;

        Ok(KeyPackage {
            index: share_package.index,
            secret_share: share_package.secret_share.value,
            public: share_package.public,
            group_public: share_package.group_public,
        })
    }
}

/// Public data that contains all the signers' public keys as well as the
/// group public key.
///
/// Used for verification purposes before publishing a signature.
pub struct PublicKeyPackage {
    /// When performing signing, the coordinator must ensure that they have the
    /// correct view of participants' public keys to perform verification before
    /// publishing a signature. `signer_pubkeys` represents all signers for a
    /// signing operation.
    pub(super) signer_pubkeys: HashMap<u16, Public>,
    /// The joint public key for the entire group.
    pub group_public: VerificationKey,
}

/// Creates secret shares for a given secret.
///
/// This function accepts a secret from which shares are generated. While in
/// FROST this secret should always be generated randomly, we allow this secret
/// to be specified for this internal function for testability.
///
/// Internally, [`generate_secret_shares`] performs verifiable secret sharing, which
/// generates shares via Shamir Secret Sharing, and then generates public
/// commitments to those shares.
///
/// More specifically, [`generate_secret_shares`]:
/// - Randomly samples of coefficients [a, b, c], this represents a secret
/// polynomial f
/// - For each participant i, their secret share is f(i)
/// - The commitment to the secret polynomial f is [g^a, g^b, g^c]
///
/// Implements [`secret_key_shard`] from the spec.
///
/// [`secret_key_shard`]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-03.html#appendix-B.1
pub fn generate_secret_shares<R: RngCore + CryptoRng>(
    secret: &Secret,
    numshares: u8,
    threshold: u8,
    mut rng: R,
) -> Result<Vec<SecretShare>, &'static str> {
    if threshold < 2 {
        return Err("Threshold cannot be less than 2");
    }

    if numshares < 2 {
        return Err("Number of shares cannot be less than the minimum threshold 2");
    }

    if threshold > numshares {
        return Err("Threshold cannot exceed numshares");
    }

    let numcoeffs = threshold - 1;

    let mut coefficients: Vec<Scalar> = Vec::with_capacity(threshold as usize);

    let mut secret_shares: Vec<SecretShare> = Vec::with_capacity(numshares as usize);

    let mut commitment: VerifiableSecretSharingCommitment =
        VerifiableSecretSharingCommitment(Vec::with_capacity(threshold as usize));

    for _ in 0..numcoeffs {
        coefficients.push(Scalar::random(&mut rng));
    }

    // Verifiable secret sharing, to make sure that participants can ensure their
    // secret is consistent with every other participant's.
    commitment
        .0
        .push(CoefficientCommitment(RISTRETTO_BASEPOINT_POINT * secret.0));

    for c in &coefficients {
        commitment
            .0
            .push(CoefficientCommitment(RISTRETTO_BASEPOINT_POINT * c));
    }

    // Evaluate the polynomial with `secret` as the constant term
    // and `coeffs` as the other coefficients at the point x=share_index,
    // using Horner's method.
    for index in 1..=numshares {
        let scalar_index = Scalar::from(index as u16);
        let mut value = Scalar::zero();

        // Polynomial evaluation, for this index
        for i in (0..numcoeffs).rev() {
            value += &coefficients[i as usize];
            value *= scalar_index;
        }
        value += secret.0;

        secret_shares.push(SecretShare {
            index: index as u16,
            value: Secret(value),
            commitment: commitment.clone(),
        });
    }

    Ok(secret_shares)
}
