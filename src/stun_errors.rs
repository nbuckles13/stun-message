use nom::error::ErrorKind;
use nom::error::ParseError;

/// Stun related parsing errors
#[derive(Debug, PartialEq)]
pub enum StunParseError<I> {
    /// The first two most significant bits in a STUN message must be zero
    InvalidMessageFirstTwoBitsError(u16),

    /// The message class, extracted from the message type field, is invalid
    InvalidMessageClassError(u16),

    /// The message method, extracted from the message type field, is invalid
    InvalidMessageMethodError(u16),

    /// The message length field is too large
    InvalidMessageLengthTooLargeError(u16),

    /// The message length field is not 4 byte aligned
    InvalidMessageLengthNotAlignedError(u16),

    /// The magic cookie field does not contain the correct value
    InvalidMagicCookieError(u32),

    Nom(I, ErrorKind),
}

impl<I> ParseError<I> for StunParseError<I> {
    fn from_error_kind(input: I, kind: ErrorKind) -> Self {
        StunParseError::Nom(input, kind)
    }

    fn append(_: I, _: ErrorKind, other: Self) -> Self {
        other
    }
}
