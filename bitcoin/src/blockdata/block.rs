// SPDX-License-Identifier: CC0-1.0

//! Bitcoin blocks.
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use core::fmt;

use hashes::{scrypt, Hash, HashEngine};

use super::Weight;
use crate::blockdata::script;
use crate::blockdata::transaction::Transaction;
use crate::consensus::{encode, Decodable, Encodable};
pub use crate::hash_types::BlockHash;
use crate::hash_types::{TxMerkleNode, WitnessCommitment, WitnessMerkleNode, Wtxid};
use crate::internal_macros::impl_consensus_encoding;
use crate::merkle_tree::compute_merkle_root_from_path;
use crate::pow::{CompactTarget, Target, Work};
use crate::prelude::*;
use crate::{io, merkle_tree, VarInt};

/// Bitcoin block header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [merkle tree] commiting to all transactions in the block.
///
/// [merkle tree]: https://en.wikipedia.org/wiki/Merkle_tree
///
/// ### Bitcoin Core References
///
/// * [CBlockHeader definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L20)
#[derive(PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Header {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,

    pub aux_data: Option<AuxPow>,
}

//impl_consensus_encoding!(Header, version, prev_blockhash, merkle_root, time, bits, nonce);
impl Decodable for Header {
    fn consensus_decode_from_finite_reader<R: io::Read + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, encode::Error> {
        let base = SimpleHeader::consensus_decode_from_finite_reader(reader)?;
        if (base.version.0 & 0x100) == 0 {
            return Ok(Header {
                version: base.version,
                prev_blockhash: base.prev_blockhash,
                merkle_root: base.merkle_root,
                time: base.time,
                bits: base.bits,
                nonce: base.nonce,
                aux_data: None,
            });
        } else {
            let aux_data = AuxPow::consensus_decode_from_finite_reader(reader)?;
            Ok(Header {
                version: base.version,
                prev_blockhash: base.prev_blockhash,
                merkle_root: base.merkle_root,
                time: base.time,
                bits: base.bits,
                nonce: base.nonce,
                aux_data: Some(aux_data),
            })
        }
    }

    fn consensus_decode<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, encode::Error> {
        use crate::io::Read as _;
        let mut r = reader.take(encode::MAX_VEC_SIZE as u64);
        let thing = SimpleHeader::consensus_decode(r.by_ref())?;
        if (thing.version.0 & 0x100) == 0 {
            return Ok(Header {
                version: thing.version,
                prev_blockhash: thing.prev_blockhash,
                merkle_root: thing.merkle_root,
                time: thing.time,
                bits: thing.bits,
                nonce: thing.nonce,
                aux_data: None,
            });
        } else {
            let aux_data = AuxPow::consensus_decode(r.by_ref())?;
            Ok(Header {
                version: thing.version,
                prev_blockhash: thing.prev_blockhash,
                merkle_root: thing.merkle_root,
                time: thing.time,
                bits: thing.bits,
                nonce: thing.nonce,
                aux_data: Some(aux_data),
            })
        }
    }
}
impl Encodable for Header {
    fn consensus_encode<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error> {
        let mut len = self.version.consensus_encode(writer)?;
        len += self.prev_blockhash.consensus_encode(writer)?;
        len += self.merkle_root.consensus_encode(writer)?;
        len += self.time.consensus_encode(writer)?;
        len += self.bits.consensus_encode(writer)?;
        len += self.nonce.consensus_encode(writer)?;
        if (self.version.0 & 0x100) != 0 {
            len += self.aux_data.as_ref().unwrap().consensus_encode(writer)?;
        }
        Ok(len)
    }
}

#[derive(Copy, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct SimpleHeader {
    /// Block version, now repurposed for soft fork signalling.
    pub version: Version,
    /// Reference to the previous block in the chain.
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block.
    pub merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner.
    pub time: u32,
    /// The target value below which the blockhash must lie.
    pub bits: CompactTarget,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
}

impl_consensus_encoding!(SimpleHeader, version, prev_blockhash, merkle_root, time, bits, nonce);

impl Header {
    /// The number of bytes that the block header contributes to the size of a block.
    // Serialized length of fields (version, prev_blockhash, merkle_root, time, bits, nonce)
    pub fn to_simple_header(&self) -> SimpleHeader {
        SimpleHeader {
            version: self.version,
            prev_blockhash: self.prev_blockhash,
            merkle_root: self.merkle_root,
            time: self.time,
            bits: self.bits,
            nonce: self.nonce,
        }
    }
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash {
        let mut engine = BlockHash::engine();
        self.to_simple_header().consensus_encode(&mut engine).expect("engines don't error");
        BlockHash::from_engine(engine)
    }

    /// Returns the pow hash.
    pub fn pow_hash(&self) -> BlockHash {
        let block_header = match &self.aux_data {
            Some(aux_data) => aux_data.parent_block,
            None => self.to_simple_header(),
        };

        let mut block = Vec::new();
        block_header.consensus_encode(&mut block).expect("consensus encode failed");

        let hash = scrypt::hash(&block);
        BlockHash::from_slice(&hash).expect("from slice failed")
    }

    /// check block header
    pub fn check(&self) -> bool {
        // check version, chainid todo!()

        /* We have auxpow. Check it.  */
        if let Some(aux_data) = &self.aux_data {
            let script = &aux_data.coinbase_tx.input[0].script_sig.to_bytes();

            // check magic number script[0..4] = 0xfabe6d6d
            let Some(pos) = script.windows(4).position(|w| w == [0xfa, 0xbe, 0x6d, 0x6d]) else {
                return false;
            };

            // head 4 + hash 32 + (extranonce, nBits) 8-12
            if script.len() < pos + 44 {
                return false;
            }

            let block_hash = self.block_hash().to_raw_hash();
            let blockchain_path_hashs = aux_data
                .blockchain_branch
                .hashes
                .iter()
                .map(|h| h.to_raw_hash())
                .collect::<Vec<_>>();
            let computed_blockchain_merkle_root = compute_merkle_root_from_path(
                block_hash,
                &blockchain_path_hashs,
                aux_data.blockchain_branch.side_mask as isize,
            );

            // merkle branch <=> merkle path
            // check blockchain branch
            // script[pos + 4.. pos + 36] = aux_data.blockchain_branch root hash
            let mut root_hash_array = script[pos + 4..pos + 36].to_vec();
            root_hash_array.reverse();
            let root_hash = BlockHash::from_slice(&root_hash_array).expect("from slice error");

            if computed_blockchain_merkle_root != root_hash.to_raw_hash() {
                return false;
            }

            // check coinbase branch
            let txid = aux_data.coinbase_tx.txid().to_raw_hash();
            let path_hashs =
                aux_data.coinbase_branch.hashes.iter().map(|h| h.to_raw_hash()).collect::<Vec<_>>();
            let computed_merkle_root = compute_merkle_root_from_path(
                txid,
                &path_hashs,
                aux_data.coinbase_branch.side_mask as isize,
            );
            if computed_merkle_root != aux_data.parent_block.merkle_root.to_raw_hash() {
                return false;
            }
        }

        // check pow hash
        if self.validate_pow(self.target()).is_err() {
            return false;
        }

        true
    }

    /// Computes the target (range [0, T] inclusive) that a blockhash must land in to be valid.
    pub fn target(&self) -> Target {
        self.bits.into()
    }

    /// Computes the popular "difficulty" measure for mining.
    pub fn difficulty(&self) -> u128 {
        self.target().difficulty()
    }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    pub fn difficulty_float(&self) -> f64 {
        self.target().difficulty_float()
    }

    /// Checks that the proof-of-work for the block is valid, returning the block hash.
    pub fn validate_pow(&self, required_target: Target) -> Result<BlockHash, ValidationError> {
        let target = self.target();
        if target != required_target {
            return Err(ValidationError::BadTarget);
        }
        let block_hash = self.pow_hash();
        if target.is_met_by(block_hash) {
            Ok(block_hash)
        } else {
            Err(ValidationError::BadProofOfWork)
        }
    }

    /// Returns the total work of the block.
    pub fn work(&self) -> Work {
        self.target().to_work()
    }
    pub fn get_size(&self) -> usize {
        /*if self.aux_data.is_none() {
            return 80
        }else{
            80 + self.aux_data.unwrap().get_size()
        }*/
        80
    }
}

impl fmt::Debug for Header {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            .field("block_hash", &self.block_hash())
            .field("version", &self.version)
            .field("prev_blockhash", &self.prev_blockhash)
            .field("merkle_root", &self.merkle_root)
            .field("time", &self.time)
            .field("bits", &self.bits)
            .field("nonce", &self.nonce)
            .finish()
    }
}

impl fmt::Debug for SimpleHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Header")
            //.field("block_hash", &self.block_hash())
            .field("version", &self.version)
            .field("prev_blockhash", &self.prev_blockhash)
            .field("merkle_root", &self.merkle_root)
            .field("time", &self.time)
            .field("bits", &self.bits)
            .field("nonce", &self.nonce)
            .finish()
    }
}

#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct MerkleBranch {
    pub hashes: Vec<BlockHash>,
    // Bitmask of which side of the merkle hash function the branch_hash element should go on.
    // Zero means it goes on the right, One means on the left.
    // It is equal to the index of the starting hash within the widest level
    // of the merkle tree for this merkle branch.
    pub side_mask: u32,
}
impl_consensus_encoding!(MerkleBranch, hashes, side_mask);

#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]

pub struct AuxPow {
    pub coinbase_tx: Transaction,
    pub block_hash: BlockHash,
    pub coinbase_branch: MerkleBranch,
    pub blockchain_branch: MerkleBranch,
    pub parent_block: SimpleHeader,
}

impl_consensus_encoding!(
    AuxPow,
    coinbase_tx,
    block_hash,
    coinbase_branch,
    blockchain_branch,
    parent_block
);
impl AuxPow {
    pub fn get_size(&self) -> usize {
        self.coinbase_tx.total_size()
            + 32
            + self.coinbase_branch.hashes.len() * 32
            + self.blockchain_branch.hashes.len() * 32
            + 80
    }
}
/// Bitcoin block version number.
///
/// Originally used as a protocol version, but repurposed for soft-fork signaling.
///
/// The inner value is a signed integer in Bitcoin Core for historical reasons, if version bits is
/// being used the top three bits must be 001, this gives us a useful range of [0x20000000...0x3FFFFFFF].
///
/// > When a block nVersion does not have top bits 001, it is treated as if all bits are 0 for the purposes of deployments.
///
/// ### Relevant BIPs
///
/// * [BIP9 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
/// * [BIP34 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
#[derive(Copy, PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Version(pub i32);

impl Version {
    /// The original Bitcoin Block v1.
    pub const ONE: Self = Self(1);

    /// BIP-34 Block v2.
    pub const TWO: Self = Self(2);

    /// BIP-9 compatible version number that does not signal for any softforks.
    pub const NO_SOFT_FORK_SIGNALLING: Self = Self(Self::USE_VERSION_BITS as i32);

    /// BIP-9 soft fork signal bits mask.
    const VERSION_BITS_MASK: u32 = 0x1FFF_FFFF;

    /// 32bit value starting with `001` to use version bits.
    ///
    /// The value has the top three bits `001` which enables the use of version bits to signal for soft forks.
    const USE_VERSION_BITS: u32 = 0x2000_0000;

    /// Creates a [`Version`] from a signed 32 bit integer value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn from_consensus(v: i32) -> Self {
        Version(v)
    }

    /// Returns the inner `i32` value.
    ///
    /// This is the data type used in consensus code in Bitcoin Core.
    pub fn to_consensus(self) -> i32 {
        self.0
    }

    /// Checks whether the version number is signalling a soft fork at the given bit.
    ///
    /// A block is signalling for a soft fork under BIP-9 if the first 3 bits are `001` and
    /// the version bit for the specific soft fork is toggled on.
    pub fn is_signalling_soft_fork(&self, bit: u8) -> bool {
        // Only bits [0, 28] inclusive are used for signalling.
        if bit > 28 {
            return false;
        }

        // To signal using version bits, the first three bits must be `001`.
        if (self.0 as u32) & !Self::VERSION_BITS_MASK != Self::USE_VERSION_BITS {
            return false;
        }

        // The bit is set if signalling a soft fork.
        (self.0 as u32 & Self::VERSION_BITS_MASK) & (1 << bit) > 0
    }
}

impl Default for Version {
    fn default() -> Version {
        Self::NO_SOFT_FORK_SIGNALLING
    }
}

impl Encodable for Version {
    fn consensus_encode<W: io::Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for Version {
    fn consensus_decode<R: io::Read + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Decodable::consensus_decode(r).map(Version)
    }
}

/// Bitcoin block.
///
/// A collection of transactions with an attached proof of work.
///
/// See [Bitcoin Wiki: Block][wiki-block] for more information.
///
/// [wiki-block]: https://en.bitcoin.it/wiki/Block
///
/// ### Bitcoin Core References
///
/// * [CBlock definition](https://github.com/bitcoin/bitcoin/blob/345457b542b6a980ccfbc868af0970a6f91d1b82/src/primitives/block.h#L62)
#[derive(PartialEq, Eq, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Block {
    /// The block header
    pub header: Header,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>,
}

impl_consensus_encoding!(Block, header, txdata);

impl Block {
    /// Returns the block hash.
    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    /// Checks if merkle root of header matches merkle root of the transaction list.
    pub fn check_merkle_root(&self) -> bool {
        match self.compute_merkle_root() {
            Some(merkle_root) => self.header.merkle_root == merkle_root,
            None => false,
        }
    }

    /// Checks if witness commitment in coinbase matches the transaction list.
    pub fn check_witness_commitment(&self) -> bool {
        const MAGIC: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        // Witness commitment is optional if there are no transactions using SegWit in the block.
        if self.txdata.iter().all(|t| t.input.iter().all(|i| i.witness.is_empty())) {
            return true;
        }

        if self.txdata.is_empty() {
            return false;
        }

        let coinbase = &self.txdata[0];
        if !coinbase.is_coinbase() {
            return false;
        }

        // Commitment is in the last output that starts with magic bytes.
        if let Some(pos) = coinbase
            .output
            .iter()
            .rposition(|o| o.script_pubkey.len() >= 38 && o.script_pubkey.as_bytes()[0..6] == MAGIC)
        {
            let commitment = WitnessCommitment::from_slice(
                &coinbase.output[pos].script_pubkey.as_bytes()[6..38],
            )
            .unwrap();
            // Witness reserved value is in coinbase input witness.
            let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
            if witness_vec.len() == 1 && witness_vec[0].len() == 32 {
                if let Some(witness_root) = self.witness_root() {
                    return commitment
                        == Self::compute_witness_commitment(&witness_root, witness_vec[0]);
                }
            }
        }

        false
    }

    /// Computes the transaction merkle root.
    pub fn compute_merkle_root(&self) -> Option<TxMerkleNode> {
        let hashes = self.txdata.iter().map(|obj| obj.txid().to_raw_hash());
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Computes the witness commitment for the block's transaction list.
    pub fn compute_witness_commitment(
        witness_root: &WitnessMerkleNode,
        witness_reserved_value: &[u8],
    ) -> WitnessCommitment {
        let mut encoder = WitnessCommitment::engine();
        witness_root.consensus_encode(&mut encoder).expect("engines don't error");
        encoder.input(witness_reserved_value);
        WitnessCommitment::from_engine(encoder)
    }

    /// Computes the merkle root of transactions hashed for witness.
    pub fn witness_root(&self) -> Option<WitnessMerkleNode> {
        let hashes = self.txdata.iter().enumerate().map(|(i, t)| {
            if i == 0 {
                // Replace the first hash with zeroes.
                Wtxid::all_zeros().to_raw_hash()
            } else {
                t.wtxid().to_raw_hash()
            }
        });
        merkle_tree::calculate_root(hashes).map(|h| h.into())
    }

    /// Returns the weight of the block.
    ///
    /// > Block weight is defined as Base size * 3 + Total size.
    pub fn weight(&self) -> Weight {
        // This is the exact definition of a weight unit, as defined by BIP-141 (quote above).
        let wu = self.base_size() * 3 + self.total_size();
        Weight::from_wu_usize(wu)
    }

    /// Returns the base block size.
    ///
    /// > Base size is the block size in bytes with the original transaction serialization without
    /// > any witness-related data, as seen by a non-upgraded node.
    fn base_size(&self) -> usize {
        let mut size = self.header.get_size();

        size += VarInt::from(self.txdata.len()).size();
        size += self.txdata.iter().map(|tx| tx.base_size()).sum::<usize>();

        size
    }

    /// Returns the total block size.
    ///
    /// > Total size is the block size in bytes with transactions serialized as described in BIP144,
    /// > including base data and witness data.
    pub fn total_size(&self) -> usize {
        let mut size = self.header.get_size();

        size += VarInt::from(self.txdata.len()).size();
        size += self.txdata.iter().map(|tx| tx.total_size()).sum::<usize>();

        size
    }

    /// Returns the stripped size of the block.
    #[deprecated(since = "0.31.0", note = "use Block::base_size() instead")]
    pub fn strippedsize(&self) -> usize {
        self.base_size()
    }

    /// Returns the coinbase transaction, if one is present.
    pub fn coinbase(&self) -> Option<&Transaction> {
        self.txdata.first()
    }

    /// Returns the block height, as encoded in the coinbase transaction according to BIP34.
    pub fn bip34_block_height(&self) -> Result<u64, Bip34Error> {
        // Citing the spec:
        // Add height as the first item in the coinbase transaction's scriptSig,
        // and increase block version to 2. The format of the height is
        // "minimally encoded serialized CScript"" -- first byte is number of bytes in the number
        // (will be 0x03 on main net for the next 150 or so years with 2^23-1
        // blocks), following bytes are little-endian representation of the
        // number (including a sign bit). Height is the height of the mined
        // block in the block chain, where the genesis block is height zero (0).

        if self.header.version < Version::TWO {
            return Err(Bip34Error::Unsupported);
        }

        let cb = self.coinbase().ok_or(Bip34Error::NotPresent)?;
        let input = cb.input.first().ok_or(Bip34Error::NotPresent)?;
        let push = input.script_sig.instructions_minimal().next().ok_or(Bip34Error::NotPresent)?;
        match push.map_err(|_| Bip34Error::NotPresent)? {
            script::Instruction::PushBytes(b) => {
                // Check that the number is encoded in the minimal way.
                let h = script::read_scriptint(b.as_bytes())
                    .map_err(|_e| Bip34Error::UnexpectedPush(b.as_bytes().to_vec()))?;
                if h < 0 {
                    Err(Bip34Error::NegativeHeight)
                } else {
                    Ok(h as u64)
                }
            }
            _ => Err(Bip34Error::NotPresent),
        }
    }

    /// Checks whether the block is valid.
    pub fn check(&self) -> bool {
        if !self.header.check() {
            return false;
        }
        if !self.check_merkle_root() {
            return false;
        }

        // check transactions todo!()

        true
    }
}

impl From<Header> for BlockHash {
    fn from(header: Header) -> BlockHash {
        header.block_hash()
    }
}

impl From<&Header> for BlockHash {
    fn from(header: &Header) -> BlockHash {
        header.block_hash()
    }
}

impl From<Block> for BlockHash {
    fn from(block: Block) -> BlockHash {
        block.block_hash()
    }
}

impl From<&Block> for BlockHash {
    fn from(block: &Block) -> BlockHash {
        block.block_hash()
    }
}

/// An error when looking up a BIP34 block height.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bip34Error {
    /// The block does not support BIP34 yet.
    Unsupported,
    /// No push was present where the BIP34 push was expected.
    NotPresent,
    /// The BIP34 push was larger than 8 bytes.
    UnexpectedPush(Vec<u8>),
    /// The BIP34 push was negative.
    NegativeHeight,
}

impl fmt::Display for Bip34Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Bip34Error::*;

        match *self {
            Unsupported => write!(f, "block doesn't support BIP34"),
            NotPresent => write!(f, "BIP34 push not present in block's coinbase"),
            UnexpectedPush(ref p) => {
                write!(f, "unexpected byte push of > 8 bytes: {:?}", p)
            }
            NegativeHeight => write!(f, "negative BIP34 height"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bip34Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Bip34Error::*;

        match *self {
            Unsupported | NotPresent | UnexpectedPush(_) | NegativeHeight => None,
        }
    }
}

/// A block validation error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValidationError {
    /// The header hash is not below the target.
    BadProofOfWork,
    /// The `target` field of a block header did not match the expected difficulty.
    BadTarget,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ValidationError::*;

        match *self {
            BadProofOfWork => f.write_str("block target correct but not attained"),
            BadTarget => f.write_str("block target incorrect"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::ValidationError::*;

        match *self {
            BadProofOfWork | BadTarget => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use hex::{test_hex_unwrap as hex, FromHex};

    use super::*;
    use crate::consensus::encode::{deserialize, serialize};

    #[test]
    fn test_coinbase_and_bip34() {
        // testnet block 100,000
        const BLOCK_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3703a08601000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let block: Block = deserialize(&hex!(BLOCK_HEX)).unwrap();

        let cb_txid = "d574f343976d8e70d91cb278d21044dd8a396019e6db70755a0a50e4783dba38";
        assert_eq!(block.coinbase().unwrap().txid().to_string(), cb_txid);

        assert_eq!(block.bip34_block_height(), Ok(100_000));

        // block with 9-byte bip34 push
        const BAD_HEX: &str = "0200000035ab154183570282ce9afc0b494c9fc6a3cfea05aa8c1add2ecc56490000000038ba3d78e4500a5a7570dbe61960398add4410d278b21cd9708e6d9743f374d544fc055227f1001c29c1ea3b0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff3d09a08601112233445566000427f1001c046a510100522cfabe6d6d0000000000000000000068692066726f6d20706f6f6c7365727665726aac1eeeed88ffffffff0100f2052a010000001976a914912e2b234f941f30b18afbb4fa46171214bf66c888ac00000000";
        let bad: Block = deserialize(&hex!(BAD_HEX)).unwrap();

        let push = Vec::<u8>::from_hex("a08601112233445566").unwrap();
        assert_eq!(bad.bip34_block_height(), Err(super::Bip34Error::UnexpectedPush(push)));
    }
    #[test]
    fn block2() {
        let dd = hex!("010000009156352c1818b32e90c9e792efd6a11a82fe7956a630f03bbee236cedae3911a1c525f1049e519256961f407e96e22aef391581de98686524ef500769f777e5fafeda352f0ff0f1e001083540101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e04afeda3520102062f503253482fffffffff01004023ef3806000023210338bf57d51a50184cf5ef0dc42ecd519fb19e24574c057620262cc1df94da2ae5ac00000000");
        let block: Block = deserialize(&dd).unwrap();
        println!("{:?}", block);
    }
    #[test]
    fn block_test() {
        // Mainnet block 00000000b0c5a240b2a61d2e75692224efd4cbecdf6eaf4cc2cf477ca7c270e7
        let some_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000");
        let cutoff_block = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b0201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac");

        let prevhash = hex!("4ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000");
        let merkle = hex!("bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c");
        let work = Work::from(0x100010001_u128);

        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(1));
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1231965655);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(486604799));
        assert_eq!(real_decode.header.nonce, 2067413810);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(), 1);
        assert_eq!(real_decode.header.difficulty_float(), 1.0);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.total_size(), some_block.len());
        assert_eq!(real_decode.base_size(), some_block.len());
        assert_eq!(
            real_decode.weight(),
            Weight::from_non_witness_data_size(some_block.len() as u64)
        );

        // should be also ok for a non-witness block as commitment is optional in that case
        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), some_block);
    }

    // Check testnet block 000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b
    #[test]
    fn segwit_block_test() {
        let segwit_block = include_bytes!("../../tests/data/testnet_block_000000000000045e0b1660b6445b5e5c5ab63c9a4f956be7e1e69be04fa4497b.raw").to_vec();

        let decode: Result<Block, _> = deserialize(&segwit_block);

        let prevhash = hex!("2aa2f2ca794ccbd40c16e2f3333f6b8b683f9e7179b2c4d74906000000000000");
        let merkle = hex!("10bc26e70a2f672ad420a6153dd0c28b40a6002c55531bfc99bf8994a8e8f67e");
        let work = Work::from(0x257c3becdacc64_u64);

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(Version::USE_VERSION_BITS as i32)); // VERSIONBITS but no bits set
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.merkle_root, real_decode.compute_merkle_root().unwrap());
        assert_eq!(real_decode.header.time, 1472004949);
        assert_eq!(real_decode.header.bits, CompactTarget::from_consensus(0x1a06d450));
        assert_eq!(real_decode.header.nonce, 1879759182);
        assert_eq!(real_decode.header.work(), work);
        assert_eq!(
            real_decode.header.validate_pow(real_decode.header.target()).unwrap(),
            real_decode.block_hash()
        );
        assert_eq!(real_decode.header.difficulty(), 2456598);
        assert_eq!(real_decode.header.difficulty_float(), 2456598.4399242126);
        // [test] TODO: check the transaction data

        assert_eq!(real_decode.total_size(), segwit_block.len());
        assert_eq!(real_decode.base_size(), 4283);
        assert_eq!(real_decode.weight(), Weight::from_wu(17168));

        assert!(real_decode.check_witness_commitment());

        assert_eq!(serialize(&real_decode), segwit_block);
    }

    #[test]
    fn block_version_test() {
        let block = hex!("ffffff7f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode: Result<Block, _> = deserialize(&block);
        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, Version(2147483647));

        let block2 = hex!("000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        let decode2: Result<Block, _> = deserialize(&block2);
        assert!(decode2.is_ok());
        let real_decode2 = decode2.unwrap();
        assert_eq!(real_decode2.header.version, Version(-2147483648));
    }

    #[test]
    fn validate_pow_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");
        let some_header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");
        assert_eq!(
            some_header.validate_pow(some_header.target()).unwrap(),
            some_header.block_hash()
        );

        // test with zero target
        match some_header.validate_pow(Target::ZERO) {
            Err(ValidationError::BadTarget) => (),
            _ => panic!("unexpected result from validate_pow"),
        }

        // test with modified header
        let mut invalid_header: Header = some_header;
        invalid_header.version.0 += 1;
        match invalid_header.validate_pow(invalid_header.target()) {
            Err(ValidationError::BadProofOfWork) => (),
            _ => panic!("unexpected result from validate_pow"),
        }
    }

    #[test]
    fn compact_roundrtip_test() {
        let some_header = hex!("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914cd74d6e49ffff001d323b3a7b");

        let header: Header =
            deserialize(&some_header).expect("Can't deserialize correct block header");

        assert_eq!(header.bits, header.target().to_compact_lossy());
    }

    #[test]
    fn soft_fork_signalling() {
        for i in 0..31 {
            let version_int = (0x20000000u32 ^ 1 << i) as i32;
            let version = Version(version_int);
            if i < 29 {
                assert!(version.is_signalling_soft_fork(i));
            } else {
                assert!(!version.is_signalling_soft_fork(i));
            }
        }

        let segwit_signal = Version(0x20000000 ^ 1 << 1);
        assert!(!segwit_signal.is_signalling_soft_fork(0));
        assert!(segwit_signal.is_signalling_soft_fork(1));
        assert!(!segwit_signal.is_signalling_soft_fork(2));
    }

    #[test]
    fn test_scrypt() {
        let block = hex::test_hex_unwrap!("020000009368a2b9ce40097ed27c4172a6abe61f8a5bddeb93db1e9d811b3922229a08bd107e3d41ea06ab190e4c9d548dd7af92f43182f9979d292e053dea95ce6d97e15f2db554d25f011ba8c7ca56");

        let mut computed_hash = scrypt::hash(&block).to_vec();
        computed_hash.reverse();

        let hash = hex::test_hex_unwrap!(
            "0000000000011b78623a435fe8e86a20a1098b7f514c78996ce1e10f627c742e"
        );

        assert_eq!(hash, computed_hash);
    }

    #[test]
    fn test_pow() {
        let some_block = hex!("040162002be721f59554324a1d2d09cf664d5e7539ac4bb0cfda9320fa49cfef1ee637b6faadcbfb4a663eb4272055a59416ae2628b4a3c9e9ea9107d5ffd52596f2cb8854f22f646374011a0000000002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4e03506b2504b1f425b1474c54432f4254432e636f6d2ffabe6d6d2405898c96c767445ef30ccdfe3b615d6da5d974348781ffea5ff6425ece74c701000000000000001b4e93400900000000000000ffffffff02e55d844a000000001976a9141cf77b08e672f1b39ae99fa7b61f4ad0aff5f10388ac0000000000000000266a24aa21a9ed4f8e12027e81153d2dae5b65168a06facfabd37da3b857b49e6bba7909e61f450000000000000000000000d194a4c8bb00a71d4ae878d32007fa4dd528354420235c8b780531ad901c2df34281009be34cf303cf4bd5bf356533ef1bec0c85e45db718b39f173ac9ead8aa7cf13b240daef254c58549bf83ed2aa242308ac34eba662602f2a8f4b9157710bdb10d46d3ca26068697924d9dcb76cdca78f0e938c70dbabcd19df70a010d3a8d31f03da171a6cdefdec8fa49e00b74e4c2abe35da9e4d3aada7eac3380bcee854b85f813429e4556dfa5ee54f1f13d5bd9040e95c3cbb66320000000000000000000000000203320d027dea67123894db182cba645b337a86bf62ad70376a171f75b79189bfc24687145b447f9d6c6eb0d7e9ff6f959e8a698e70c5f7d7b6488487d04264cec53f22f6498b0001a6c45a3e70501000000010000000000000000000000000000000000000000000000000000000000000000ffffffff06032a35470101ffffffff01e0a1d3d4e80000001976a914ce344e1860c1e9e50521860dc1b3a90bc14097aa88ac00000000010000000113c938b01d9bafe1a2b4939f32df91ae22db4cb910450e1d45c73070db042f47000000006b483045022100f18debb5714f4a87bf87da3bc141fcfe7b519ea6ff32c244b6a934383137843e022035c71d00877eab609164f3adce1089dc16d5920ccde0b7abba385d58613da28f012102975a05460682397129b029473c462b0bc7efe65ccb1823210ce814e25629f389ffffffff026e344910680000001976a914a8cb446b4f846d31fb4f5d214ffaaaaac09d297b88ac0078a698200000001976a91467fc0fb53c13a179773b7c15416cb172a5e5a9c788ac000000000100000002b7f8f82bc48cd82d0ce8ed207cc32cc9edc366f8130b4969f9b4e041c9138174010000006b483045022100a5fcb723b89fd27ce460b4f0c53752098c981fe9b05d77000866b90fb40a8089022043b80a84900ca59264d268dd2ef760066cc74253a59d02799c5eaf91021d0d120121026d50509424080183b2936ad0ca47197140b7750232f9c5e67ea97213a6aaf030feffffff826abb1f5e5580141eb7e0d391d8c5b598285920d9af0c84bfc5a48717c2a9390000000049483045022100d639250d192ce710f69b54ca1ad9e2e0c5985c14385bebd6fedbf7ed1e1bb49602205d27fd338119da6433ef1bbe0f7623fe75b204d32f3fdc38feaba79e7b8f837401feffffff0217e8dae0e80000001976a914aae6a94f80accc7775de871ba6bdb181dd26a6bd88aca0822c00000000001976a91487a4309438c4804b7985974bb2f7aabd0e0cdb2588ac2835470001000000013742c6297193e84421f3328c5f6dd411bf31b609ce8489ae635e522c011015db000000006a47304402202699b16460a01299554251d61d3a95193a66b40b78b6256439b7c243f7a7e20a0220267ad65491289d684d55426f0fcf1644975a98af9b64b0dd619de75ba776d93d01210378787e36184e23f3b49248ac55d8556ad4d97489575d682a039ebb54dd1d31d9feffffff0236231864040000001976a914c85aeb2c3377ca6b062dab1bd18ae172d1ca8f0c88acfa8d13fe400000001976a914cdc1863d9bdbf04668113a5c12dd343c1cbb9ee888ac28354700010000000193eb1c1cf26e1b5487a9c17f5e2684c59eecbd97f45740ed3729cda1023077b3010000006a47304402203cebcd1b26b1c8d4bca937ef2df397d54676e2e0b6cbc5166cbdc1d9f78bbfbe022071ed43c440a57c2921150e29695ab042dac0c223909680c12632b95a0c9d5f0a012102ea5ae89718633a81e7e90f7049e200ff4ebe9fb5277704125089639b2fa09b93feffffff0260c106f00f0000001976a914d9b896cccf9847802331f6fcf303b96f2e4ff5da88ac40420f00000000001976a914d151e2118a3b1f86abb45a5b32621342d67d554888ac28354700");
        let block: Block = deserialize(&some_block).expect("Can't deserialize correct block");

        let pow_hash = block.header.pow_hash();
        assert_eq!(block.header.validate_pow(block.header.bits.into()), Ok(pow_hash));
    }

    #[test]
    fn check_block() {
        // dogecoin block https://dogechain.info/block/4666666
        // litecoin privious block https://ltc.tokenview.io/cn/block/2452303
        let some_block = hex!("040162002be721f59554324a1d2d09cf664d5e7539ac4bb0cfda9320fa49cfef1ee637b6faadcbfb4a663eb4272055a59416ae2628b4a3c9e9ea9107d5ffd52596f2cb8854f22f646374011a0000000002000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4e03506b2504b1f425b1474c54432f4254432e636f6d2ffabe6d6d2405898c96c767445ef30ccdfe3b615d6da5d974348781ffea5ff6425ece74c701000000000000001b4e93400900000000000000ffffffff02e55d844a000000001976a9141cf77b08e672f1b39ae99fa7b61f4ad0aff5f10388ac0000000000000000266a24aa21a9ed4f8e12027e81153d2dae5b65168a06facfabd37da3b857b49e6bba7909e61f450000000000000000000000d194a4c8bb00a71d4ae878d32007fa4dd528354420235c8b780531ad901c2df34281009be34cf303cf4bd5bf356533ef1bec0c85e45db718b39f173ac9ead8aa7cf13b240daef254c58549bf83ed2aa242308ac34eba662602f2a8f4b9157710bdb10d46d3ca26068697924d9dcb76cdca78f0e938c70dbabcd19df70a010d3a8d31f03da171a6cdefdec8fa49e00b74e4c2abe35da9e4d3aada7eac3380bcee854b85f813429e4556dfa5ee54f1f13d5bd9040e95c3cbb66320000000000000000000000000203320d027dea67123894db182cba645b337a86bf62ad70376a171f75b79189bfc24687145b447f9d6c6eb0d7e9ff6f959e8a698e70c5f7d7b6488487d04264cec53f22f6498b0001a6c45a3e70501000000010000000000000000000000000000000000000000000000000000000000000000ffffffff06032a35470101ffffffff01e0a1d3d4e80000001976a914ce344e1860c1e9e50521860dc1b3a90bc14097aa88ac00000000010000000113c938b01d9bafe1a2b4939f32df91ae22db4cb910450e1d45c73070db042f47000000006b483045022100f18debb5714f4a87bf87da3bc141fcfe7b519ea6ff32c244b6a934383137843e022035c71d00877eab609164f3adce1089dc16d5920ccde0b7abba385d58613da28f012102975a05460682397129b029473c462b0bc7efe65ccb1823210ce814e25629f389ffffffff026e344910680000001976a914a8cb446b4f846d31fb4f5d214ffaaaaac09d297b88ac0078a698200000001976a91467fc0fb53c13a179773b7c15416cb172a5e5a9c788ac000000000100000002b7f8f82bc48cd82d0ce8ed207cc32cc9edc366f8130b4969f9b4e041c9138174010000006b483045022100a5fcb723b89fd27ce460b4f0c53752098c981fe9b05d77000866b90fb40a8089022043b80a84900ca59264d268dd2ef760066cc74253a59d02799c5eaf91021d0d120121026d50509424080183b2936ad0ca47197140b7750232f9c5e67ea97213a6aaf030feffffff826abb1f5e5580141eb7e0d391d8c5b598285920d9af0c84bfc5a48717c2a9390000000049483045022100d639250d192ce710f69b54ca1ad9e2e0c5985c14385bebd6fedbf7ed1e1bb49602205d27fd338119da6433ef1bbe0f7623fe75b204d32f3fdc38feaba79e7b8f837401feffffff0217e8dae0e80000001976a914aae6a94f80accc7775de871ba6bdb181dd26a6bd88aca0822c00000000001976a91487a4309438c4804b7985974bb2f7aabd0e0cdb2588ac2835470001000000013742c6297193e84421f3328c5f6dd411bf31b609ce8489ae635e522c011015db000000006a47304402202699b16460a01299554251d61d3a95193a66b40b78b6256439b7c243f7a7e20a0220267ad65491289d684d55426f0fcf1644975a98af9b64b0dd619de75ba776d93d01210378787e36184e23f3b49248ac55d8556ad4d97489575d682a039ebb54dd1d31d9feffffff0236231864040000001976a914c85aeb2c3377ca6b062dab1bd18ae172d1ca8f0c88acfa8d13fe400000001976a914cdc1863d9bdbf04668113a5c12dd343c1cbb9ee888ac28354700010000000193eb1c1cf26e1b5487a9c17f5e2684c59eecbd97f45740ed3729cda1023077b3010000006a47304402203cebcd1b26b1c8d4bca937ef2df397d54676e2e0b6cbc5166cbdc1d9f78bbfbe022071ed43c440a57c2921150e29695ab042dac0c223909680c12632b95a0c9d5f0a012102ea5ae89718633a81e7e90f7049e200ff4ebe9fb5277704125089639b2fa09b93feffffff0260c106f00f0000001976a914d9b896cccf9847802331f6fcf303b96f2e4ff5da88ac40420f00000000001976a914d151e2118a3b1f86abb45a5b32621342d67d554888ac28354700");
        let block: Block = deserialize(&some_block).expect("Can't deserialize correct block");

        assert_eq!(block.check_merkle_root(), true);
        assert_eq!(block.check(), true);
    }
}

#[cfg(bench)]
mod benches {
    use test::{black_box, Bencher};

    use super::Block;
    use crate::consensus::{deserialize, Decodable, Encodable};
    use crate::EmptyWrite;

    #[bench]
    pub fn bench_stream_reader(bh: &mut Bencher) {
        let big_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");
        assert_eq!(big_block.len(), 1_381_836);
        let big_block = black_box(big_block);

        bh.iter(|| {
            let mut reader = &big_block[..];
            let block = Block::consensus_decode(&mut reader).unwrap();
            black_box(&block);
        });
    }

    #[bench]
    pub fn bench_block_serialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        let mut data = Vec::with_capacity(raw_block.len());

        bh.iter(|| {
            let result = block.consensus_encode(&mut data);
            black_box(&result);
            data.clear();
        });
    }

    #[bench]
    pub fn bench_block_serialize_logic(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        let block: Block = deserialize(&raw_block[..]).unwrap();

        bh.iter(|| {
            let size = block.consensus_encode(&mut EmptyWrite);
            black_box(&size);
        });
    }

    #[bench]
    pub fn bench_block_deserialize(bh: &mut Bencher) {
        let raw_block = include_bytes!("../../tests/data/mainnet_block_000000000000000000000c835b2adcaedc20fdf6ee440009c249452c726dafae.raw");

        bh.iter(|| {
            let block: Block = deserialize(&raw_block[..]).unwrap();
            black_box(&block);
        });
    }
}
