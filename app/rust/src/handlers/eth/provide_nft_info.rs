/*******************************************************************************
*   (c) 2018-2024 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use crate::{constants::ApduError as Error, dispatcher::ApduHandler, sys, utils::ApduBufferRead};

pub struct Info;

#[cfg(feature = "erc721")]
impl Info {
    /// Store the NFT descriptor in `input` for the next ERC-721 review, with
    /// whether Ledger's NFT metadata key signed it.
    ///
    /// The review shows the collection name as the NFT being moved or
    /// approved. The host can bind any name to any contract, so a
    /// descriptor Ledger did not sign (the JS SDK's provideNFTInformation
    /// sends one with a random signature) is stored as unverified and the
    /// review titles its name "NFT (unverified)"; a Ledger-signed one gets
    /// the plain "Collection Name" titles. A malformed descriptor is
    /// refused, and drops any descriptor stored before it, so the review
    /// falls back to showing the contract call without a name.
    pub fn process(input: &[u8]) -> Result<(), Error> {
        use crate::parser::SignedNftDescriptor;

        crate::zlog("NftInfo::process\x00");

        // A parsed transaction holds the info from its parse until its
        // review is answered, and the ERC-721 review reads the collection
        // name from it at every screen. Taking the slot from under it would
        // make the rest of that review fail to render, and replacing it
        // would change the name it shows, so the info stays untouched.
        if Self::held_by_review() {
            return Err(Error::ApduCodeConditionsNotSatisfied);
        }

        let parsed = SignedNftDescriptor::parse(input).and_then(|d| d.info());

        // held by the provider until the next sign request claims it; a
        // refused descriptor also drops whatever an earlier one left
        let stored = unsafe { crate::lock_mut!(crate::handlers::resources::NFT_INFO).lock(Info) };

        match parsed {
            Ok(nft_info) => {
                if nft_info.verified() {
                    crate::zlog("NftInfo verified\x00");
                } else {
                    crate::zlog("NftInfo unverified\x00");
                }
                stored.replace(nft_info);
                Ok(())
            }
            Err(_) => {
                stored.take();
                Err(Error::DataInvalid)
            }
        }
    }

    /// Whether a parsed ETH transaction holds NFT info for its review.
    /// Looking does not change who holds it.
    fn held_by_review() -> bool {
        use crate::handlers::resources::NFT_INFO;
        use crate::parser::ERC721Info;

        unsafe { matches!(crate::lock_mut!(NFT_INFO).acquire(ERC721Info), Ok(Some(_))) }
    }
}

#[cfg(not(feature = "erc721"))]
impl Info {
    fn process(_: &[u8]) -> Result<(), Error> {
        Ok(())
    }
}

impl ApduHandler for Info {
    #[inline(never)]
    fn handle(_flags: &mut u32, tx: &mut u32, buffer: ApduBufferRead<'_>) -> Result<(), Error> {
        sys::zemu_log_stack("NftInfoProvider::handle\x00");

        *tx = 0;

        // the hw-app-eth sends all the data that is required for this.
        // it is arount 90 bytes length so It should error in case It received
        // less than that
        let payload = buffer.payload().map_err(|_| Error::WrongLength)?;

        Info::process(payload)?;

        Ok(())
    }
}
