use arrayvec::CapacityError;
use nom::error::ErrorKind;
use zemu_sys::ViewError;

#[repr(u32)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
// #[cfg_attr(test, derive(Debug))]
pub enum ParserError {
    // Every discriminant is pinned to its parser_error_t counterpart in
    // app/src/common/parser_common.h: the FFI passes these to C verbatim
    // (`e as u32`), where they pick the error string shown to the host and,
    // for BlindSignNotEnabled, whether the blind-sign warning screen is shown.
    // Keep the two in lockstep; c_enum_matches checks it.
    ParserOk = 0,
    // Generic errors
    NoData = 1,
    DisplayIdxOutOfRange = 2,
    DisplayPageOutOfRange = 3,
    UnexpectedError = 4,
    ParserInitContextEmpty = 5,
    ParserContextMismatch = 6,
    UnexpectedType = 7,
    UnexpectedField = 8,
    UnexpectedBufferEnd = 9,
    ValueOutOfRange = 10,
    InvalidAddress = 11,
    UnexpectedNumberItems = 12,
    // Coin specific
    InvalidHashMode = 13,
    InvalidSignature = 14,
    InvalidPubkeyEncoding = 15,
    InvalidAddressVersion = 16,
    InvalidAddressLength = 17,
    InvalidTypeId = 18,
    InvalidCodec = 19,
    InvalidThreshold = 20,
    InvalidNetworkId = 21,
    InvalidChainId = 22,
    InvalidAsciiValue = 23,
    InvalidTimestamp = 24,
    InvalidStakingAmount = 25,
    InvalidTransactionType = 26,
    OperationOverflows = 27,
    UnexpectedData = 28,
    InvalidPath = 29,
    TooManyOutputs = 30,
    InvalidAvaxMessage = 31,
    InvalidEthMessage = 32,
    InvalidEthSelector = 33,
    InvalidAssetCall = 34,
    NftInfoNotProvided = 35,
    InvalidContractAddress = 36,
    ContextUnexpectedSize = 37,
    TooManyAddresses = 38,
    InvalidMessageSize = 39,
    InvalidCodecId = 40,
    InvalidLength = 41,
    // The C side (apdu_handler.c) compares against this exact value to decide
    // whether to show the blind-sign warning screen.
    BlindSignNotEnabled = 42,
    InvalidSourceAddressSize = 43,
}

impl From<ErrorKind> for ParserError {
    fn from(err: ErrorKind) -> Self {
        match err {
            ErrorKind::Eof => ParserError::UnexpectedBufferEnd,
            ErrorKind::Permutation => ParserError::UnexpectedType,
            ErrorKind::TooLarge => ParserError::ValueOutOfRange,
            ErrorKind::Tag => ParserError::InvalidTypeId,
            _ => ParserError::UnexpectedError,
        }
    }
}

// ViewError::Unknown is 0, which C reads as parser_ok: a render error cast
// straight to u32 was reported as success and zxlib skipped the item. Every
// variant must map to a non-zero error, and not to NoData either: tx_getItem
// turns parser_no_data into zxerr_no_data, which the Nano X/S+ review takes
// as the end of the items and jumps to approval.
impl From<ViewError> for ParserError {
    fn from(err: ViewError) -> Self {
        match err {
            ViewError::Unknown | ViewError::NoData | ViewError::Reject => {
                ParserError::UnexpectedError
            }
        }
    }
}

impl<I> nom::error::ParseError<I> for ParserError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        Self::from(kind)
    }

    // We don't have enough memory resources to use here an array with the last
    // N errors to be used as a backtrace, so that, we just propagate here the latest
    // reported error
    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}
impl From<ParserError> for nom::Err<ParserError> {
    fn from(error: ParserError) -> Self {
        nom::Err::Error(error)
    }
}

impl From<CapacityError> for ParserError {
    fn from(_error: CapacityError) -> Self {
        ParserError::UnexpectedBufferEnd
    }
}

impl From<nom::Err<Self>> for ParserError {
    fn from(e: nom::Err<Self>) -> Self {
        match e {
            nom::Err::Error(e) => e,
            nom::Err::Failure(e) => e,
            nom::Err::Incomplete(_) => Self::UnexpectedBufferEnd,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::prelude::v1::*;

    /// Every variant, with its parser_error_t name. The match keeps the list
    /// exhaustive: a new variant does not compile until it is added here.
    fn c_name(e: ParserError) -> &'static str {
        use ParserError::*;
        match e {
            ParserOk => "parser_ok",
            NoData => "parser_no_data",
            DisplayIdxOutOfRange => "parser_display_idx_out_of_range",
            DisplayPageOutOfRange => "parser_display_page_out_of_range",
            UnexpectedError => "parser_unexpected_error",
            ParserInitContextEmpty => "parser_init_context_empty",
            ParserContextMismatch => "parser_context_mismatch",
            UnexpectedType => "parser_unexpected_type",
            UnexpectedField => "parser_unexpected_field",
            UnexpectedBufferEnd => "parser_unexpected_buffer_end",
            ValueOutOfRange => "parser_value_out_of_range",
            InvalidAddress => "parser_invalid_address",
            UnexpectedNumberItems => "parser_unexpected_number_items",
            InvalidHashMode => "parser_invalid_hash_mode",
            InvalidSignature => "parser_invalid_signature",
            InvalidPubkeyEncoding => "parser_invalid_pubkey_encoding",
            InvalidAddressVersion => "parser_invalid_address_version",
            InvalidAddressLength => "parser_invalid_address_length",
            InvalidTypeId => "parser_invalid_type_id",
            InvalidCodec => "parser_invalid_codec",
            InvalidThreshold => "parser_invalid_threshold",
            InvalidNetworkId => "parser_invalid_network_id",
            InvalidChainId => "parser_invalid_chain_id",
            InvalidAsciiValue => "parser_invalid_ascii_value",
            InvalidTimestamp => "parser_invalid_timestamp",
            InvalidStakingAmount => "parser_invalid_staking_amount",
            InvalidTransactionType => "parser_invalid_transaction_type",
            OperationOverflows => "parser_operation_overflows",
            UnexpectedData => "parser_unexpected_data",
            InvalidPath => "parser_invalid_path",
            TooManyOutputs => "parser_too_many_outputs",
            InvalidAvaxMessage => "parser_invalid_avax_message",
            InvalidEthMessage => "parser_invalid_eth_message",
            InvalidEthSelector => "parser_invalid_eth_selector",
            InvalidAssetCall => "parser_invalid_asset_call",
            NftInfoNotProvided => "parser_nft_info_not_provided",
            InvalidContractAddress => "parser_invalid_contract_address",
            ContextUnexpectedSize => "parser_context_unexpected_size",
            TooManyAddresses => "parser_too_many_addresses",
            InvalidMessageSize => "parser_invalid_message_size",
            InvalidCodecId => "parser_invalid_codec_id",
            InvalidLength => "parser_invalid_length",
            BlindSignNotEnabled => "parser_blind_sign_not_enabled",
            InvalidSourceAddressSize => "parser_invalid_source_address_size",
        }
    }

    const ALL: &[ParserError] = {
        use ParserError::*;
        &[
            ParserOk,
            NoData,
            DisplayIdxOutOfRange,
            DisplayPageOutOfRange,
            UnexpectedError,
            ParserInitContextEmpty,
            ParserContextMismatch,
            UnexpectedType,
            UnexpectedField,
            UnexpectedBufferEnd,
            ValueOutOfRange,
            InvalidAddress,
            UnexpectedNumberItems,
            InvalidHashMode,
            InvalidSignature,
            InvalidPubkeyEncoding,
            InvalidAddressVersion,
            InvalidAddressLength,
            InvalidTypeId,
            InvalidCodec,
            InvalidThreshold,
            InvalidNetworkId,
            InvalidChainId,
            InvalidAsciiValue,
            InvalidTimestamp,
            InvalidStakingAmount,
            InvalidTransactionType,
            OperationOverflows,
            UnexpectedData,
            InvalidPath,
            TooManyOutputs,
            InvalidAvaxMessage,
            InvalidEthMessage,
            InvalidEthSelector,
            InvalidAssetCall,
            NftInfoNotProvided,
            InvalidContractAddress,
            ContextUnexpectedSize,
            TooManyAddresses,
            InvalidMessageSize,
            InvalidCodecId,
            InvalidLength,
            BlindSignNotEnabled,
            InvalidSourceAddressSize,
        ]
    };

    /// `parser_xxx = N` entries of the C parser_error_t.
    fn c_enum() -> Vec<(String, u32)> {
        let header = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../src/common/parser_common.h"
        ))
        .expect("read parser_common.h");
        let body = header
            .split("typedef enum {")
            .nth(1)
            .and_then(|rest| rest.split("} parser_error_t;").next())
            .expect("parser_error_t in parser_common.h");

        body.lines()
            .filter_map(|line| {
                let (name, value) = line.trim().trim_end_matches(',').split_once('=')?;
                Some((name.trim().to_string(), value.trim().parse().ok()?))
            })
            .collect()
    }

    #[test]
    fn c_enum_matches() {
        let c = c_enum();
        assert_eq!(c.len(), ALL.len(), "C and Rust list different errors");

        for e in ALL {
            let name = c_name(*e);
            let value = c
                .iter()
                .find(|(c_name, _)| c_name == name)
                .unwrap_or_else(|| panic!("{name} missing from parser_error_t"))
                .1;
            assert_eq!(*e as u32, value, "{e:?} differs from {name}");
        }
    }

    #[test]
    fn view_errors_are_never_parser_ok() {
        for e in [ViewError::Unknown, ViewError::NoData, ViewError::Reject] {
            let err = ParserError::from(e);
            assert_ne!(err, ParserError::ParserOk);
            assert_ne!(err, ParserError::NoData);
        }
    }
}
