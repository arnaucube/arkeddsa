use crate::{signature::Signature, Error};
use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    Absorb, CryptographicSponge,
};
use ark_ec::{
    twisted_edwards::{Affine, TECurveConfig},
    AffineRepr,
};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use digest::Digest;
use digest::OutputSizeUser;
use rand_core::CryptoRngCore;

fn prune_buffer<F: PrimeField>(mut bytes: [u8; 32]) -> F {
    bytes[0] &= 0b1111_1000;
    bytes[31] &= 0b0111_1111;
    bytes[31] |= 0b0100_0000;
    F::from_le_bytes_mod_order(&bytes[..])
}

#[derive(Copy, Clone, Debug)]
/// EdDSA secret key is 32 byte data
pub struct SecretKey([u8; 32]);

impl SecretKey {
    fn expand<F: PrimeField, D: Digest>(&self) -> (F, [u8; 32]) {
        let hash = D::new().chain_update(self.0).finalize();
        let (buffer, hash_prefix) = hash.split_at(32);
        let buffer: [u8; 32] = buffer.try_into().unwrap();
        let hash_prefix: [u8; 32] = hash_prefix.try_into().unwrap();
        let x = prune_buffer(buffer);
        (x, hash_prefix)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self(bytes.clone())
    }
}

/// `PublicKey` is EdDSA signature verification key
#[derive(Copy, Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKey<TE: TECurveConfig>(Affine<TE>);

impl<TE: TECurveConfig> PublicKey<TE> {
    pub fn xy(&self) -> Result<(&TE::BaseField, &TE::BaseField), Error> {
        self.as_ref().xy().ok_or(Error::Coordinates)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn ark_std::error::Error>> {
        let point = Affine::<TE>::deserialize_compressed(bytes)?;
        Ok(Self(point))
    }
}

impl<TE: TECurveConfig> From<Affine<TE>> for PublicKey<TE> {
    fn from(affine: Affine<TE>) -> Self {
        Self(affine)
    }
}

impl<TE: TECurveConfig> AsRef<Affine<TE>> for PublicKey<TE> {
    fn as_ref(&self) -> &Affine<TE> {
        &self.0
    }
}

#[derive(Copy, Clone, Debug)]
/// `SigningKey` produces EdDSA signatures for given message
pub struct SigningKey<TE: TECurveConfig> {
    secret_key: SecretKey,
    public_key: PublicKey<TE>,
}

impl<TE: TECurveConfig + Clone> SigningKey<TE>
where
    TE::BaseField: PrimeField + Absorb,
{
    pub fn new<D: Digest>(secret_key: &SecretKey) -> Result<Self, Error> {
        (<D as OutputSizeUser>::output_size() == 64)
            .then_some(())
            .ok_or(Error::BadDigestOutput)?;

        let (x, _) = secret_key.expand::<TE::ScalarField, D>();
        let public_key: Affine<TE> = (Affine::<TE>::generator() * x).into();
        let signing_key = Self {
            secret_key: *secret_key,
            public_key: PublicKey(public_key),
        };

        Ok(signing_key)
    }

    pub fn from_bytes<D: Digest>(bytes: &[u8; 32]) -> Result<Self, Error> {
        let secret_key = SecretKey::from_bytes(bytes);
        Self::new::<D>(&secret_key)
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret_key.to_bytes()
    }

    pub fn generate<D: Digest>(rng: &mut impl CryptoRngCore) -> Result<Self, Error> {
        let mut secret_key = SecretKey([0; 32]);
        rng.fill_bytes(&mut secret_key.0);
        Self::new::<D>(&secret_key)
    }

    pub fn public_key(&self) -> &PublicKey<TE> {
        &self.public_key
    }

    pub fn sign<D: Digest>(
        &self,
        poseidon: &PoseidonConfig<TE::BaseField>,
        message: &TE::BaseField,
    ) -> Result<Signature<TE>, Error> {
        let (x, prefix) = self.secret_key.expand::<TE::ScalarField, D>();

        let mut h = D::new();
        h.update(prefix);
        let msg_bytes = message.into_bigint().to_bytes_le();
        let mut msg32: [u8; 32] = [0; 32];
        msg32[..msg_bytes.len()].copy_from_slice(&msg_bytes[..]);
        h.update(msg32);

        let r: TE::ScalarField = crate::from_digest(h);
        let sig_r: Affine<TE> = (Affine::<TE>::generator() * r).into();

        let mut poseidon = PoseidonSponge::new(poseidon);

        let (sig_r_x, sig_r_y) = sig_r.xy().ok_or(Error::Coordinates)?;
        poseidon.absorb(sig_r_x);
        poseidon.absorb(sig_r_y);
        let (pk_x, pk_y) = self.public_key.0.xy().ok_or(Error::Coordinates)?;
        poseidon.absorb(pk_x);
        poseidon.absorb(pk_y);
        poseidon.absorb(message);

        // use poseidon over Fq, so that it can be done too in-circuit
        let k = poseidon.squeeze_field_elements::<TE::BaseField>(1);
        let k = k.first().ok_or(Error::BadDigestOutput)?;
        let k = TE::ScalarField::from_le_bytes_mod_order(&k.into_bigint().to_bytes_le());

        let sig_s = (x * k) + r;

        Ok(Signature::new(sig_r, sig_s))
    }
}

impl<TE: TECurveConfig> SigningKey<TE> {
    pub fn shared_key<D: Digest>(&self, recipient: &PublicKey<TE>) -> [u8; 32] {
        let (x, _) = self.secret_key.expand::<TE::ScalarField, D>();
        let shared_key: Affine<TE> = (*recipient.as_ref() * x).into();
        let mut data = Vec::new();
        shared_key.serialize_compressed(&mut data).unwrap();
        data[00..32].try_into().unwrap()
    }
}

impl<TE: TECurveConfig + Clone> PublicKey<TE>
where
    TE::BaseField: PrimeField + Absorb,
{
    pub fn verify(
        &self,
        poseidon: &PoseidonConfig<TE::BaseField>,
        message: &TE::BaseField,
        signature: &Signature<TE>,
    ) -> Result<(), Error> {
        let mut poseidon = PoseidonSponge::new(poseidon);

        let (sig_r_x, sig_r_y) = signature.r().xy().ok_or(Error::Coordinates)?;
        poseidon.absorb(sig_r_x);
        poseidon.absorb(sig_r_y);
        let (pk_x, pk_y) = self.0.xy().ok_or(Error::Coordinates)?;
        poseidon.absorb(pk_x);
        poseidon.absorb(pk_y);
        poseidon.absorb(message);

        // use poseidon over Fq, so that it can be done too in-circuit
        let k = poseidon.squeeze_field_elements::<TE::BaseField>(1);
        let k = k.first().ok_or(Error::BadDigestOutput)?;

        let kx_b = self.0.mul_bigint(k.into_bigint());
        let s_b = Affine::<TE>::generator() * signature.s();
        let r_rec: Affine<TE> = (s_b - kx_b).into();

        (signature.r() == &r_rec).then_some(()).ok_or(Error::Verify)
    }
}
