/// A Stun attribute, https://tools.ietf.org/html/rfc5389#section-15
///
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |         Type                  |            Length             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Value (variable)                ....
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#[derive(Debug)]
pub struct StunAttribute<'a> {
    /// attribute type -- 2 bytes
    pub attribute_type: u16,

    /// attribute length (of just the value part, w/o padding) -- 2 bytes
    pub attribute_length: u16,

    /// attribute value -- length bytes
    pub attribute_value: &'a [u8],
}
