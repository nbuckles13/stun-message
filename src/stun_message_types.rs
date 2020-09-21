use num_enum::TryFromPrimitive;

/// Stun message classes
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u16)]
pub enum StunMessageClass {
    Request = 0b00,
    Indication = 0b01,
    SuccessResponse = 0b10,
    ErrorResponse = 0b11,
}

/// Stun message methods
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, Clone, Copy)]
#[repr(u16)]
pub enum StunMessageMethod {
    Binding = 0b00,
}
