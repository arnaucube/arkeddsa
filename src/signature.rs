use ark_ec::twisted_edwards::Affine;
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::CurveGroup;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;

/// `SignatureComponents` contains the realized parts of a signature
#[derive(Copy, Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Signature<C: CurveGroup + Clone> {
    pub r: C::Affine,
    pub s: C::ScalarField,
}

impl<C: CurveGroup + Clone> Signature<C> {
    /*
    /// Serializes the signature components to bytes as uncompressed.
    /// Expect output size to be `size_of(C::BaseField) * 2 + size_of(C::ScalarField)`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.r.serialize_uncompressed(&mut bytes).unwrap();
        self.s.serialize_uncompressed(&mut bytes).unwrap();
        bytes
    }

    /// Checked deserialization of the signature components from bytes.
    /// Expects input size to be `size_of(C::BaseField) * 2 + size_of(C::ScalarField)`
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Box<dyn ark_std::error::Error>> {
        let point_size = C::Affine::Config::serialized_size(ark_serialize::Compress::No);
        (bytes.len() == 32 + C::Affine::Config::serialized_size(ark_serialize::Compress::No))
            .then_some(true)
            .ok_or(ark_serialize::SerializationError::InvalidData)?;

        let off1 = point_size;
        let off2 = off1 + 32;

        let r = C::Affine::deserialize_uncompressed(&bytes[00..off1])?;
        let s = C::ScalarField::deserialize_uncompressed(&bytes[off1..off2])?;
        Ok(Signature { r, s })
    }
    */

    pub fn new(r: C::Affine, s: C::ScalarField) -> Self {
        Self { r, s }
    }

    pub fn r(&self) -> &C::Affine {
        &self.r
    }

    pub fn s(&self) -> &C::ScalarField {
        &self.s
    }
}
