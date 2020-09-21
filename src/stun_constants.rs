/// Bitmask to extract the mandatory zero bits from a STUN message type
pub const STUN_MESSAGE_TYPE_ZERO_MASK: u16 = 0b1100_0000_0000_0000;

/// Bitmask to extract the class value from a STUN message type
pub const STUN_MESSAGE_CLASS_MASK: u16 = 0b0000_0001_0001_0000;

/// Bitmask to extract the separated bits of the class value
pub const STUN_MESSAGE_CLASS_MASK_BIT_0: u16 = 0b0000_0000_0001_0000;
pub const STUN_MESSAGE_CLASS_MASK_BIT_1: u16 = 0b0000_0001_0000_0000;

/// Shift value to put the separated bits of the class value into position
pub const STUN_MESSAGE_CLASS_SHIFT_BIT_0: usize = 4;
pub const STUN_MESSAGE_CLASS_SHIFT_BIT_1: usize = 7;

/// Bitmask to extract the method value from a STUN message type
pub const STUN_MESSAGE_METHOD_MASK: u16 = 0b0011_1110_1110_1111;

/// Bitmask to extract the separated bits that comprise the STUN message method
pub const STUN_MESSAGE_METHOD_MASK_BIT_0_3: u16 = 0b0000_0000_0000_1111;
pub const STUN_MESSAGE_METHOD_MASK_BIT_4_6: u16 = 0b0000_0000_1110_0000;
pub const STUN_MESSAGE_METHOD_MASK_BIT_7_11: u16 = 0b0011_1110_0000_0000;

/// Shift value to put the separated bits of the method value into position
pub const STUN_MESSAGE_METHOD_SHIFT_BIT_0_3: usize = 0;
pub const STUN_MESSAGE_METHOD_SHIFT_BIT_4_6: usize = 1;
pub const STUN_MESSAGE_METHOD_SHIFT_BIT_7_11: usize = 2;

/// STUN magic cookie value
pub const STUN_MAGIC_COOKIE: u32 = 0x2112_A442;

/// Number of bytes in a STUN transaction id
pub const STUN_TRANSACTION_ID_NUM_BYTES: usize = 12;

/// Number of bytes in the fixed STUN header after the length field
pub const STUN_FIXED_HEADER_AFTER_LENGTH_NUM_BYTES: usize = STUN_TRANSACTION_ID_NUM_BYTES + 4;