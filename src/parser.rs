use crate::stun_attribute::*;
use crate::stun_constants::*;
use crate::stun_errors::StunParseError;
use crate::stun_message::*;
use crate::stun_message_types::*;

use std::convert::TryFrom;
use std::convert::TryInto;

extern crate nom;
use nom::bytes::complete::take;
use nom::multi::many0;
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::tuple;
use nom::Err::Error;
use nom::IResult;

/// Parse a STUN message from the given input buffer.
///
/// # Arguments
///
/// @param input an array containing a serialized STUN message
///
/// # Return
///
/// A nom::IResult object.  On success a tuple containing the unparsed portion of the input
/// buffer and a StunMessage object.  On error, an error object describing the error.
/// @see https://docs.rs/nom/0.3.5/nom/enum.IResult.html
pub fn parse_stun_message(input: &[u8]) -> IResult<&[u8], StunMessage, StunParseError<&[u8]>> {
    let (
        input,
        ((message_class, message_method), message_length, magic_cookie, transaction_id, attributes),
    ) = tuple((
        parse_message_type,
        parse_message_length,
        parse_magic_cookie,
        parse_transaction_id,
        parse_attributes,
    ))(input)?;

    Ok((
        input,
        StunMessage {
            message_class,
            message_method,
            message_length,
            magic_cookie,
            transaction_id,
            attributes,
        },
    ))
}

fn parse_message_type(
    input: &[u8],
) -> IResult<&[u8], (StunMessageClass, StunMessageMethod), StunParseError<&[u8]>> {
    let (input, message_type) = be_u16(input)?;

    let (input, _) = parse_leading_zero(input, message_type)?;
    let (input, message_class) = parse_message_class(input, message_type)?;
    let (input, message_method) = parse_message_method(input, message_type)?;

    Ok((input, (message_class, message_method)))
}

fn parse_leading_zero(
    input: &[u8],
    message_type: u16,
) -> IResult<&[u8], (), StunParseError<&[u8]>> {
    let zero_bits = message_type & STUN_MESSAGE_TYPE_ZERO_MASK;

    match zero_bits {
        0 => Ok((input, ())),
        _ => Err(Error(StunParseError::InvalidMessageFirstTwoBitsError(
            message_type,
        ))),
    }
}

fn parse_message_class(
    input: &[u8],
    message_type: u16,
) -> IResult<&[u8], StunMessageClass, StunParseError<&[u8]>> {
    let class_bits = ((message_type & STUN_MESSAGE_CLASS_MASK_BIT_0)
        >> STUN_MESSAGE_CLASS_SHIFT_BIT_0)
        | ((message_type & STUN_MESSAGE_CLASS_MASK_BIT_1) >> STUN_MESSAGE_CLASS_SHIFT_BIT_1);

    match StunMessageClass::try_from(class_bits) {
        Ok(class) => Ok((input, class)),
        Err(_) => Err(Error(StunParseError::InvalidMessageClassError(
            message_type,
        ))),
    }
}

fn parse_message_method(
    input: &[u8],
    message_type: u16,
) -> IResult<&[u8], StunMessageMethod, StunParseError<&[u8]>> {
    let method_bits = ((message_type & STUN_MESSAGE_METHOD_MASK_BIT_0_3)
        >> STUN_MESSAGE_METHOD_SHIFT_BIT_0_3)
        | ((message_type & STUN_MESSAGE_METHOD_MASK_BIT_4_6) >> STUN_MESSAGE_METHOD_SHIFT_BIT_4_6)
        | ((message_type & STUN_MESSAGE_METHOD_MASK_BIT_7_11)
            >> STUN_MESSAGE_METHOD_SHIFT_BIT_7_11);

    match StunMessageMethod::try_from(method_bits) {
        Ok(method) => Ok((input, method)),
        Err(_) => Err(Error(StunParseError::InvalidMessageMethodError(
            message_type,
        ))),
    }
}

fn parse_message_length(input: &[u8]) -> IResult<&[u8], u16, StunParseError<&[u8]>> {
    let (input, message_length) = be_u16(input)?;

    // message length must be a multiple of 4
    if message_length % 4 != 0 {
        return Err(Error(StunParseError::InvalidMessageLengthNotAlignedError(
            message_length,
        )));
    }

    // message length must not be longer than the input buffer
    // note that message length does not include the magic cookie or transaction id, which are 16 bytes in total
    let min_remaining_size = message_length as usize + STUN_FIXED_HEADER_AFTER_LENGTH_NUM_BYTES;
    if min_remaining_size > input.len() {
        return Err(Error(StunParseError::InvalidMessageLengthTooLargeError(
            message_length,
        )));
    }

    Ok((input, message_length))
}

fn parse_magic_cookie(input: &[u8]) -> IResult<&[u8], u32, StunParseError<&[u8]>> {
    let (input, magic_cookie) = be_u32(input)?;

    match magic_cookie {
        STUN_MAGIC_COOKIE => Ok((input, magic_cookie)),
        _ => Err(Error(StunParseError::InvalidMagicCookieError(magic_cookie))),
    }
}

fn parse_transaction_id(input: &[u8]) -> IResult<&[u8], &[u8; 12], StunParseError<&[u8]>> {
    let (input, transaction_id) = take(STUN_TRANSACTION_ID_NUM_BYTES)(input)?;

    Ok((input, transaction_id.try_into().unwrap()))
}

fn parse_attributes(input: &[u8]) -> IResult<&[u8], Vec<StunAttribute>, StunParseError<&[u8]>> {
    many0(parse_attribute)(input)
}

fn parse_attribute(input: &[u8]) -> IResult<&[u8], StunAttribute, StunParseError<&[u8]>> {
    let (input, attribute_type) = be_u16(input)?;
    let (input, attribute_length) = be_u16(input)?;
    let (input, attribute_value) = take(attribute_length as usize)(input)?;

    // attributes must end on 4 byte boundaries, so if the length is not on a 4 byte boundary then we must consume extra bytes
    let padding_length: usize = match attribute_length % 4 {
        1 => 3,
        2 => 2,
        3 => 1,
        _ => 0,
    };
    let (input, _) = take(padding_length)(input)?;

    Ok((
        input,
        StunAttribute {
            attribute_type,
            attribute_length,
            attribute_value,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_message_type_valid_helper(
        message_type: u16,
        expected_class: StunMessageClass,
        expected_method: StunMessageMethod,
    ) {
        let input: [u8; 2] = [
            ((message_type & 0xFF00) >> 8) as u8,
            (message_type & 0x00FF) as u8,
        ];
        let result = parse_message_type(&input);

        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.1, (expected_class, expected_method));
    }

    #[test]
    fn parse_message_type_valid() {
        parse_message_type_valid_helper(
            0x0000,
            StunMessageClass::Request,
            StunMessageMethod::Binding,
        );
        parse_message_type_valid_helper(
            0x0010,
            StunMessageClass::Indication,
            StunMessageMethod::Binding,
        );
        parse_message_type_valid_helper(
            0x0100,
            StunMessageClass::SuccessResponse,
            StunMessageMethod::Binding,
        );
        parse_message_type_valid_helper(
            0x0110,
            StunMessageClass::ErrorResponse,
            StunMessageMethod::Binding,
        );
    }

    fn parse_message_type_invalid_helper(message_type: u16, expected_error: StunParseError<&[u8]>) {
        let input: [u8; 2] = [
            ((message_type & 0xFF00) >> 8) as u8,
            (message_type & 0x00FF) as u8,
        ];
        let result = parse_message_type(&input);

        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            Error(e) => assert_eq!(e, expected_error),
            _ => panic!("Unexpected error:  {:?}", err),
        }
    }

    #[test]
    fn parse_message_type_invalid_first_two_bits() {
        parse_message_type_invalid_helper(
            0xC000,
            StunParseError::InvalidMessageFirstTwoBitsError(0xC000),
        );
    }

    #[test]
    fn parse_message_type_invalid_method() {
        parse_message_type_invalid_helper(
            0x000F,
            StunParseError::InvalidMessageMethodError(0x000F),
        );
    }

    #[test]
    fn parse_message_length_valid_empty() {
        // note that as part of length parsing, we also validate that the indicated length matches the size of
        // the remaining input, so we need to make the input buffer the expected size
        let input: [u8; 18] = [0; 18];
        let result = parse_message_length(&input);

        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.1, 0);
    }

    #[test]
    fn parse_message_length_valid_non_empty() {
        // note that as part of length parsing, we also validate that the indicated length matches the size of
        // the remaining input, so we need to make the input buffer the expected size
        let mut input: [u8; 22] = [0; 22];
        input[1] = 0x4;

        let result = parse_message_length(&input);

        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.1, 4);
    }

    #[test]
    fn parse_message_length_invalid_not_aligned() {
        // the length field must be a multiple of 4
        let mut input: [u8; 21] = [0; 21];
        input[1] = 0x3;

        let result = parse_message_length(&input);

        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            Error(e) => assert_eq!(
                e,
                StunParseError::InvalidMessageLengthNotAlignedError(0x0003)
            ),
            _ => panic!("Unexpected error:  {:?}", err),
        }
    }

    #[test]
    fn parse_message_length_invalid_too_large() {
        // the length field says the input buffer should be bigger than it is
        let mut input: [u8; 21] = [0; 21];
        input[1] = 0x4;

        let result = parse_message_length(&input);

        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            Error(e) => assert_eq!(e, StunParseError::InvalidMessageLengthTooLargeError(0x0004)),
            _ => panic!("Unexpected error:  {:?}", err),
        }
    }

    #[test]
    fn parse_magic_cookie_valid() {
        let input: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
        let result = parse_magic_cookie(&input);

        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.1, STUN_MAGIC_COOKIE);
    }

    #[test]
    fn parse_magic_cookie_invalid() {
        let input: [u8; 4] = [0; 4];
        let result = parse_magic_cookie(&input);

        assert!(result.is_err());

        let err = result.unwrap_err();
        match err {
            Error(e) => assert_eq!(e, StunParseError::InvalidMagicCookieError(0x00000000)),
            _ => panic!("Unexpected error:  {:?}", err),
        }
    }

    #[test]
    fn parse_transaction_id_valid() {
        let input: [u8; 12] = [0; 12];
        let result = parse_transaction_id(&input);

        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.1, &input);
    }

    #[test]
    fn parse_attribute_valid_empty() {
        let input: [u8; 4] = [0x00, 0x01, 0x00, 0x00];
        let result = parse_attribute(&input);

        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.1.attribute_type, 0x0001);
        assert_eq!(data.1.attribute_length, 0x0000);
        assert_eq!(data.1.attribute_value.len(), 0);
    }

    #[test]
    fn parse_attribute_valid_non_empty() {
        let input: [u8; 8] = [0x00, 0x01, 0x00, 0x04, 0x0A, 0x0B, 0x0C, 0x0D];
        let result = parse_attribute(&input);

        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.1.attribute_type, 0x0001);
        assert_eq!(data.1.attribute_length, 0x0004);
        assert_eq!(data.1.attribute_value, &input[4..8]);
    }

    #[test]
    fn parse_attribute_valid_non_empty_padding() {
        let input: [u8; 8] = [0x00, 0x01, 0x00, 0x03, 0x0A, 0x0B, 0x0C, 0x0D];
        let result = parse_attribute(&input);

        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.0.len(), 0);
        assert_eq!(data.1.attribute_type, 0x0001);
        assert_eq!(data.1.attribute_length, 0x0003);
        assert_eq!(data.1.attribute_value, &input[4..7]);
    }

    #[test]
    fn parse_attribute_invalid_missing_padding() {
        let input: [u8; 7] = [0x00, 0x01, 0x00, 0x03, 0x0A, 0x0B, 0x0C];
        let result = parse_attribute(&input);

        assert!(result.is_err());
    }

    #[test]
    fn parse_attribute_invalid_length() {
        let input: [u8; 8] = [0x00, 0x01, 0x00, 0x08, 0x0A, 0x0B, 0x0C, 0x0D];
        let result = parse_attribute(&input);

        assert!(result.is_err());
    }

    #[test]
    fn parse_stun_message_valid() {
        let input = vec![
            0x00, 0x00, // message type
            0x00, 0x0C, // message length
            0x21, 0x12, 0xA4, 0x42, // magic cookie
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, // transaction id
            0xAB, 0xCD, // first attribute type
            0x00, 0x00, // first attribute length
            0xEF, 0xFE, // second attribute type
            0x00, 0x03, // second attribute length
            0xAA, 0xBB, 0xCC, // second attribute value
            0x00, // second attribute padding
        ];
        let result = parse_stun_message(&input);

        assert!(result.is_ok());

        let data = result.unwrap();
        assert_eq!(data.0.len(), 0);

        assert_eq!(data.1.message_class, StunMessageClass::Request);
        assert_eq!(data.1.message_method, StunMessageMethod::Binding);
        assert_eq!(data.1.message_length, 12);
        assert_eq!(data.1.magic_cookie, STUN_MAGIC_COOKIE);
        assert_eq!(data.1.transaction_id, &input[8..20]);
        assert_eq!(data.1.attributes.len(), 2);
        assert_eq!(data.1.attributes[0].attribute_type, 0xABCD);
        assert_eq!(data.1.attributes[0].attribute_length, 0);
        assert_eq!(data.1.attributes[0].attribute_value, []);
        assert_eq!(data.1.attributes[1].attribute_type, 0xEFFE);
        assert_eq!(data.1.attributes[1].attribute_length, 3);
        assert_eq!(data.1.attributes[1].attribute_value, [0xAA, 0xBB, 0xCC]);
    }
}
