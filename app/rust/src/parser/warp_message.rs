use crate::parser::{
    proof_of_possession::BLS_SIGNATURE_LEN, AddressedCall, FromBytes, NetworkId, ParserError,
};
use core::mem::MaybeUninit;
use nom::{
    bytes::complete::take,
    number::complete::{be_u16, be_u32},
};

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
#[cfg_attr(test, derive(Debug))]
pub struct WarpMessage<'b> {
    pub codec_id: u16,
    pub network_id: NetworkId,
    pub source_chain_id: &'b [u8; 32],
    pub payload: AddressedCall<'b>,
}

impl<'b> FromBytes<'b> for WarpMessage<'b> {
    fn from_bytes_into(
        input: &'b [u8],
        out: &mut MaybeUninit<Self>,
    ) -> Result<&'b [u8], nom::Err<ParserError>> {
        crate::sys::zemu_log_stack("WarpMessage::from_bytes_into\x00");

        let out = out.as_mut_ptr();

        // codecID (2 bytes)
        let (rem, codec_id) = be_u16(input)?;

        if codec_id != 0 {
            return Err(nom::Err::Error(ParserError::InvalidCodecId));
        }

        // networkID (4 bytes)
        let (rem, network_id) = be_u32(rem)?;
        let network_id =
            NetworkId::try_from(network_id).map_err(|_| ParserError::InvalidNetworkId)?;

        // sourceChainId (32 bytes)
        let (rem, source_chain_id) = take(32usize)(rem)?;
        let source_chain_id = arrayref::array_ref!(source_chain_id, 0, 32);

        // payload_size (4 bytes)
        let (rem, payload_size) = be_u32(rem)?;

        // Slice exactly the declared payload before handing it on, the same
        // way AddressedCall bounds its own payload. Ignoring payload_size and
        // passing the rest of the buffer let surplus bytes sit inside the warp
        // region: AddressedCall consumed only what its own header declared,
        // and the surplus was covered by the signing hash without ever
        // reaching a screen.
        let (outer_rem, payload_bytes) = take(payload_size as usize)(rem)?;

        // addressed_call - parse the payload as AddressedCall
        let addressed_call = unsafe { &mut *core::ptr::addr_of_mut!((*out).payload).cast() };
        let after_payload = AddressedCall::from_bytes_into(payload_bytes, addressed_call)?;
        if !after_payload.is_empty() {
            return Err(nom::Err::Error(ParserError::UnexpectedData));
        }

        unsafe {
            core::ptr::addr_of_mut!((*out).codec_id).write(codec_id);
            core::ptr::addr_of_mut!((*out).network_id).write(network_id);
            core::ptr::addr_of_mut!((*out).source_chain_id).write(source_chain_id);
        }

        // Callers hand this function a slice bounded to the declared warp size,
        // so whatever is left here belongs to the warp message itself. A signed
        // message carries a BitSetSignature -- type id, the signer bitset as a
        // length-prefixed byte string, then the aggregate BLS signature; an
        // unsigned one carries nothing. Neither is displayed, but both have to
        // be walked: leaving a tail unparsed is exactly what allowed "declared
        // size" and "bytes accounted for" to be different numbers.
        let rem = if outer_rem.is_empty() {
            outer_rem
        } else {
            let (rem, _signature_type_id) = be_u32(outer_rem)?;
            let (rem, signers_len) = be_u32(rem)?;
            let (rem, _signers) = take(signers_len as usize)(rem)?;
            let (rem, _signature) = take(BLS_SIGNATURE_LEN)(rem)?;
            rem
        };

        // Anything still here is a byte the declared size covered, the hash
        // covers, and no screen shows.
        Ok(rem)
    }
}
