use crate::stun_attribute::*;
use crate::stun_constants::*;
use crate::stun_message::*;
use crate::stun_message_types::*;

use cookie_factory::bytes::{be_u16, be_u32};
use cookie_factory::combinator::slice;
use cookie_factory::multi::many_ref;
use cookie_factory::sequence::tuple;
use cookie_factory::{gen, GenError, SerializeFn};

use std::io::Write;

/// Serialize the given STUN message into the given output.
///
/// # Arguments
///
/// * `message` - The STUN message to serialize
/// * `output` - The buffer to serialize into
///
/// # Return
///
/// A Result object, when successful contains the number of bytes written to output.
pub fn serialize_into(message: &StunMessage, output: &mut [u8]) -> Result<u64, GenError> {
    gen(serialize_helper(message), output).map(|res| res.1)
}

/// Serialize the given STUN message into a dynamically allocated output
///
/// # Arguments
///
/// * `message` - The STUN message to serialize
///
/// # Return
///
/// A Result object, when successful contains a Vec<u8> holding the serialized message
pub fn serialize(message: &StunMessage) -> Result<Vec<u8>, GenError> {
    let mut output = Vec::with_capacity(2048);

    gen(serialize_helper(message), &mut output).map(|res| res.0.to_vec())
}

fn serialize_helper<'a, W: Write + 'a>(message: &'a StunMessage) -> impl SerializeFn<W> + 'a {
    tuple((
        serialize_message_type(message),
        be_u16(message.message_length),
        be_u32(message.magic_cookie),
        slice(message.transaction_id),
        many_ref(&message.attributes, serialize_attribute),
    ))
}

fn serialize_message_type<W: Write>(message: &StunMessage) -> impl SerializeFn<W> {
    let message_type = serialize_message_class(message.message_class)
        | serialize_message_method(message.message_method);

    be_u16(message_type)
}

fn serialize_message_class(message_class: StunMessageClass) -> u16 {
    let message_class = message_class as u16;

    // shift the two bits into their proper position
    ((message_class & 0x0001) << STUN_MESSAGE_CLASS_SHIFT_BIT_0)
        | ((message_class & 0x0002) << STUN_MESSAGE_CLASS_SHIFT_BIT_1)
}

fn serialize_message_method(message_method: StunMessageMethod) -> u16 {
    let message_method = message_method as u16;

    // shift all the bits into their proper position
    ((message_method & 0x000F) << STUN_MESSAGE_METHOD_SHIFT_BIT_0_3)
        | (message_method & 0x0070 << STUN_MESSAGE_METHOD_SHIFT_BIT_4_6)
        | (message_method & 0x0F80 << STUN_MESSAGE_METHOD_SHIFT_BIT_7_11)
}

fn serialize_attribute<'a, W: Write + 'a>(a: &'a StunAttribute) -> impl SerializeFn<W> + 'a {
    tuple((
        be_u16(a.attribute_type),
        be_u16(a.attribute_length),
        slice(a.attribute_value),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_message_class() {
        assert_eq!(serialize_message_class(StunMessageClass::Request), 0x0000);
        assert_eq!(
            serialize_message_class(StunMessageClass::Indication),
            0x0010
        );
        assert_eq!(
            serialize_message_class(StunMessageClass::SuccessResponse),
            0x0100
        );
        assert_eq!(
            serialize_message_class(StunMessageClass::ErrorResponse),
            0x0110
        );
    }

    #[test]
    fn test_serialize_message_method() {
        assert_eq!(serialize_message_method(StunMessageMethod::Binding), 0x0000);
    }

    #[test]
    fn test_serialize_message_type() {
        let transaction_id = [0u8; STUN_TRANSACTION_ID_NUM_BYTES];
        let stun_message = StunMessage {
            message_class: StunMessageClass::ErrorResponse,
            message_method: StunMessageMethod::Binding,
            message_length: 0,
            magic_cookie: STUN_MAGIC_COOKIE,
            transaction_id: &transaction_id,
            attributes: vec![],
        };

        let mut output = [0xFFu8; 2];
        let result = gen(serialize_message_type(&stun_message), &mut output[..]);

        assert!(result.is_ok());
        assert_eq!(output, [0x01, 0x10]);
    }

    #[test]
    fn test_serialize_into_buffer_too_small() {
        let transaction_id = [0u8; STUN_TRANSACTION_ID_NUM_BYTES];
        let stun_message = StunMessage {
            message_class: StunMessageClass::Request,
            message_method: StunMessageMethod::Binding,
            message_length: 0,
            magic_cookie: STUN_MAGIC_COOKIE,
            transaction_id: &transaction_id,
            attributes: vec![],
        };

        let mut output = [0u8; 0];

        let result = serialize_into(&stun_message, &mut output);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialize_into() {
        let transaction_id = [0x12; STUN_TRANSACTION_ID_NUM_BYTES];
        let stun_message = StunMessage {
            message_class: StunMessageClass::Request,
            message_method: StunMessageMethod::Binding,
            message_length: 0,
            magic_cookie: STUN_MAGIC_COOKIE,
            transaction_id: &transaction_id,
            attributes: vec![],
        };

        let mut output = [0u8; 2048];

        let result = serialize_into(&stun_message, &mut output);
        assert!(result.is_ok());

        assert_eq!(result.unwrap(), 20);
        assert_eq!(output[0..2], [0x00, 0x00]);
        assert_eq!(output[2..4], [0x00, 0x00]);
        assert_eq!(output[4..8], [0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(output[8..20], transaction_id);
    }

    #[test]
    fn test_serialize_vector() {
        let transaction_id = [0x34; STUN_TRANSACTION_ID_NUM_BYTES];
        let stun_message = StunMessage {
            message_class: StunMessageClass::ErrorResponse,
            message_method: StunMessageMethod::Binding,
            message_length: 0x10,
            magic_cookie: STUN_MAGIC_COOKIE,
            transaction_id: &transaction_id,
            attributes: vec![],
        };

        let result = serialize(&stun_message);
        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.len(), 20);
        assert_eq!(data[0..2], [0x01, 0x10]);
        assert_eq!(data[2..4], [0x00, 0x10]);
        assert_eq!(data[4..8], [0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(data[8..20], transaction_id);
    }

    #[test]
    fn test_serialize_with_attribute_vector() {
        let transaction_id = [0x34; STUN_TRANSACTION_ID_NUM_BYTES];
        let stun_attribute_value = [0x56; 4];
        let stun_attribute = StunAttribute {
            attribute_type: 0x1122,
            attribute_length: 0x0004,
            attribute_value: &stun_attribute_value,
        };
        let stun_message = StunMessage {
            message_class: StunMessageClass::ErrorResponse,
            message_method: StunMessageMethod::Binding,
            message_length: 0x10,
            magic_cookie: STUN_MAGIC_COOKIE,
            transaction_id: &transaction_id,
            attributes: vec![stun_attribute],
        };

        let result = serialize(&stun_message);
        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.len(), 28);
        assert_eq!(data[0..2], [0x01, 0x10]);
        assert_eq!(data[2..4], [0x00, 0x10]);
        assert_eq!(data[4..8], [0x21, 0x12, 0xA4, 0x42]);
        assert_eq!(data[8..20], transaction_id);
        assert_eq!(data[20..22], [0x11, 0x22]);
        assert_eq!(data[22..24], [0x00, 0x04]);
        assert_eq!(data[24..28], stun_attribute_value);
    }
}
