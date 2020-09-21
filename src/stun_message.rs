use crate::stun_message_types::*;
use crate::stun_constants::*;
use crate::stun_attribute::*;

/// A STUN packet, https://tools.ietf.org/html/rfc5389#page-10
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |0 0|     STUN Message Type     |         Message Length        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Magic Cookie                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                     Transaction ID (96 bits)                  |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug)]
pub struct StunMessage<'a> {
    /// message class, encoded into message type
    pub message_class: StunMessageClass,

    /// message method, encoded into message type
    pub message_method: StunMessageMethod,

    /// message length -- 16 bits
    pub message_length: u16,

    /// magic cookie -- 32 bits
    pub magic_cookie: u32,

    /// transaction id -- 96 bits
    pub transaction_id: &'a [u8; STUN_TRANSACTION_ID_NUM_BYTES],

    /// 0 or more attributes -- N bytes
    pub attributes: Vec<StunAttribute<'a>>
}
