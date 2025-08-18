use crate::{Public, PublicBox, Secret};
use base64::Engine;
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

fn encode_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_b64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| format!("Couldn't decode base64: {e}"))
}

struct B64BytesVisitor;

impl<'de> Visitor<'de> for B64BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a base64-encoded string")
    }

    fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
        decode_b64(v).map_err(E::custom)
    }

    fn visit_string<E: DeError>(self, v: String) -> Result<Self::Value, E> {
        self.visit_str(&v)
    }
}

impl<const N: usize> Serialize for Secret<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_b64(self.secret()))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Secret<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = deserializer.deserialize_string(B64BytesVisitor)?;
        if bytes.len() != N {
            return Err(D::Error::custom(format!(
                "Unexpected length: got {}, expected {}",
                bytes.len(),
                N
            )));
        }
        // Copies from heap bytes into the internal storage;
        // no large stack temporaries.
        Ok(Secret::<N>::from_slice(bytes.as_slice()))
    }
}

impl<const N: usize> Serialize for Public<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_b64(&self.value))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Public<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = deserializer.deserialize_string(B64BytesVisitor)?;
        if bytes.len() != N {
            return Err(D::Error::custom(format!(
                "Unexpected length: got {}, expected {}",
                bytes.len(),
                N
            )));
        }
        Ok(Public::<N>::from_slice(bytes.as_slice()))
    }
}

impl<const N: usize> Serialize for PublicBox<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_b64(self.inner.value.as_slice()))
    }
}

impl<'de, const N: usize> Deserialize<'de> for PublicBox<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = deserializer.deserialize_string(B64BytesVisitor)?;
        if bytes.len() != N {
            return Err(D::Error::custom(format!(
                "Unexpected length: got {}, expected {}",
                bytes.len(),
                N
            )));
        }
        // Allocate Public<N> on the heap and copy bytes into it
        let mut inner = Box::new(Public::<N>::zero());
        inner.copy_from_slice(bytes.as_slice());
        Ok(PublicBox { inner })
    }
}
