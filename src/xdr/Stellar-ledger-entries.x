// Copyright 2015 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

%#include "xdr/Stellar-types.h"

namespace stellar
{

typedef PublicKey AccountID;
typedef opaque Thresholds[4];
typedef string string32<32>;
typedef string string64<64>;
typedef int64 SequenceNumber;
typedef uint64 TimePoint;
typedef opaque DataValue<64>;

// 1-4 alphanumeric characters right-padded with 0 bytes
typedef opaque AssetCode4[4];

// 5-12 alphanumeric characters right-padded with 0 bytes
typedef opaque AssetCode12[12];

enum AssetType
{
    ASSET_TYPE_NATIVE = 0,
    ASSET_TYPE_CREDIT_ALPHANUM4 = 1,
    ASSET_TYPE_CREDIT_ALPHANUM12 = 2
};

union Asset switch (AssetType type)
{
case ASSET_TYPE_NATIVE: // Not credit
    void;

case ASSET_TYPE_CREDIT_ALPHANUM4:
    struct
    {
        AssetCode4 assetCode;
        AccountID issuer;
    } alphaNum4;

case ASSET_TYPE_CREDIT_ALPHANUM12:
    struct
    {
        AssetCode12 assetCode;
        AccountID issuer;
    } alphaNum12;

    // add other asset types here in the future
};

// price in fractional representation
struct Price
{
    int32 n; // numerator
    int32 d; // denominator
};

struct Liabilities
{
    int64 buying;
    int64 selling;
};

// the 'Thresholds' type is packed uint8_t values
// defined by these indexes
enum ThresholdIndexes
{
    THRESHOLD_MASTER_WEIGHT = 0,
    THRESHOLD_LOW = 1,
    THRESHOLD_MED = 2,
    THRESHOLD_HIGH = 3
};

enum LedgerEntryType
{
    ACCOUNT = 0,
    TRUSTLINE = 1,
    OFFER = 2,
    DATA = 3,
    CLAIMABLE_BALANCE = 4,
    SPONSORSHIP = 5,
    PREAUTHORIZATION = 6
};

struct Signer
{
    SignerKey key;
    uint32 weight; // really only need 1 byte
};

enum AccountFlags
{ // masks for each flag

    // Flags set on issuer accounts
    // TrustLines are created with authorized set to "false" requiring
    // the issuer to set it for each TrustLine
    AUTH_REQUIRED_FLAG = 0x1,
    // If set, the authorized flag in TrustLines can be cleared
    // otherwise, authorization cannot be revoked
    AUTH_REVOCABLE_FLAG = 0x2,
    // Once set, causes all AUTH_* flags to be read-only
    AUTH_IMMUTABLE_FLAG = 0x4
};

// mask for all valid flags
const MASK_ACCOUNT_FLAGS = 0x7;

/* AccountEntry

    Main entry representing a user in Stellar. All transactions are
    performed using an account.

    Other ledger entries created require an account.

*/
struct AccountEntry
{
    AccountID accountID;      // master public key for this account
    int64 balance;            // in stroops
    SequenceNumber seqNum;    // last sequence number used for this account
    uint32 numSubEntries;     // number of sub-entries this account has
                              // drives the reserve
    AccountID* inflationDest; // Account to vote for during inflation
    uint32 flags;             // see AccountFlags

    string32 homeDomain; // can be used for reverse federation and memo lookup

    // fields used for signatures
    // thresholds stores unsigned bytes: [weight of master|low|medium|high]
    Thresholds thresholds;

    Signer signers<20>; // possible signers for this account

    // reserved for future use
    union switch (int v)
    {
    case 0:
        void;
    case 1:
        struct
        {
            Liabilities liabilities;

            union switch (int v)
            {
            case 0:
                void;
            }
            ext;
        } v1;
    }
    ext;
};

/* TrustLineEntry
    A trust line represents a specific trust relationship with
    a credit/issuer (limit, authorization)
    as well as the balance.
*/

enum TrustLineFlags
{
    // issuer has authorized account to perform transactions with its credit
    AUTHORIZED_FLAG = 1,
    // issuer has authorized account to maintain and reduce liabilities for its
    // credit
    AUTHORIZED_TO_MAINTAIN_LIABILITIES_FLAG = 2
};

// mask for all trustline flags
const MASK_TRUSTLINE_FLAGS = 1;
const MASK_TRUSTLINE_FLAGS_V13 = 3;

struct TrustLineEntry
{
    AccountID accountID; // account this trustline belongs to
    Asset asset;         // type of asset (with issuer)
    int64 balance;       // how much of this asset the user has.
                         // Asset defines the unit for this;

    int64 limit;  // balance cannot be above this
    uint32 flags; // see TrustLineFlags

    // reserved for future use
    union switch (int v)
    {
    case 0:
        void;
    case 1:
        struct
        {
            Liabilities liabilities;

            union switch (int v)
            {
            case 0:
                void;
            }
            ext;
        } v1;
    }
    ext;
};

enum OfferEntryFlags
{
    // issuer has authorized account to perform transactions with its credit
    PASSIVE_FLAG = 1
};

// Mask for OfferEntry flags
const MASK_OFFERENTRY_FLAGS = 1;

/* OfferEntry
    An offer is the building block of the offer book, they are automatically
    claimed by payments when the price set by the owner is met.

    For example an Offer is selling 10A where 1A is priced at 1.5B

*/
struct OfferEntry
{
    AccountID sellerID;
    int64 offerID;
    Asset selling; // A
    Asset buying;  // B
    int64 amount;  // amount of A

    /* price for this offer:
        price of A in terms of B
        price=AmountB/AmountA=priceNumerator/priceDenominator
        price is after fees
    */
    Price price;
    uint32 flags; // see OfferEntryFlags

    // reserved for future use
    union switch (int v)
    {
    case 0:
        void;
    }
    ext;
};

/* DataEntry
    Data can be attached to accounts.
*/
struct DataEntry
{
    AccountID accountID; // account this data belongs to
    string64 dataName;
    DataValue dataValue;

    // reserved for future use
    union switch (int v)
    {
    case 0:
        void;
    }
    ext;
};

enum ClaimPredicateType
{
    CLAIM_PREDICATE_UNCONDITIONAL = 0,
    CLAIM_PREDICATE_AND = 1,
    CLAIM_PREDICATE_OR = 2,
    CLAIM_PREDICATE_BEFORE_ABSOLUTE_TIME = 3,
    CLAIM_PREDICATE_AFTER_ABSOLUTE_TIME = 4,
    CLAIM_PREDICATE_BEFORE_RELATIVE_TIME = 5,
    CLAIM_PREDICATE_AFTER_RELATIVE_TIME = 6
};

union ClaimPredicate switch (ClaimPredicateType type)
{
case CLAIM_PREDICATE_UNCONDITIONAL:
    void;
case CLAIM_PREDICATE_AND:
    ClaimPredicate andPredicates<2>;
case CLAIM_PREDICATE_OR:
    ClaimPredicate orPredicates<2>;
case CLAIM_PREDICATE_BEFORE_ABSOLUTE_TIME:
    int64 absBefore;
case CLAIM_PREDICATE_AFTER_ABSOLUTE_TIME:
    int64 absAfter;
case CLAIM_PREDICATE_BEFORE_RELATIVE_TIME:
    int64 relBefore;    // Seconds since closeTime of the ledger in which the
                        // ClaimableBalanceEntry was created
case CLAIM_PREDICATE_AFTER_RELATIVE_TIME:
    int64 relAfter;     // Seconds since closeTime of the ledger in which the
                        // ClaimableBalanceEntry was created
};

enum ClaimantType
{
    CLAIMANT_TYPE_V0 = 0
};

union Claimant switch (ClaimantType type)
{
case CLAIMANT_TYPE_V0:
    struct {
        AccountID destination;    // The account that can use this condition
        ClaimPredicate predicate; // Claimable if predicate is true
    } v0;
};

enum ClaimableBalanceIDType
{
    CLAIMABLE_BALANCE_ID_TYPE_V0 = 0
};

union ClaimableBalanceID switch (ClaimableBalanceIDType type)
{
case CLAIMABLE_BALANCE_ID_TYPE_V0:
    Hash v0;
};

struct ClaimableBalanceEntry
{
    // Unique identifier for this ClaimableBalanceEntry
    ClaimableBalanceID balanceID;

    // Account that created this ClaimableBalanceEntry
    AccountID createdBy;

    // List of claimants with associated predicate
    Claimant claimants<10>;

    // Any asset including native
    Asset asset;

    // Amount of asset
    int64 amount;

    // Amount of native asset to pay the reserve
    int64 reserve;

    // reserved for future use
    union switch (int v)
    {
    case 0:
        void;
    }
    ext;
};

enum SponsorshipType
{
    ACCOUNT_SPONSORSHIP = 0,
    SIGNER_SPONSORSHIP = 1,
    TRUSTLINE_SPONSORSHIP = 2,
    OFFER_SPONSORSHIP = 3,
    DATA_SPONSORSHIP = 4
};

struct AccountSponsorship
{
    // Account to sponsor
    AccountID accountID;
};

struct SignerSponsorship
{
    // Account for which to sponsor the signer
    AccountID accountID;
};

struct TrustLineSponsorship
{
    // Account for which to sponsor the trust line
    AccountID accountID;

    // Trust line asset
    Asset asset;
};

struct OfferSponsorship
{
    // Account for which to sponsor the offer
    AccountID sellerID;

    // Offer must be buying this asset
    Asset buying;

    // Offer must be selling this asset
    Asset selling;
};

struct DataSponsorship
{
    // Account for which to sponsor the data
    AccountID accountID;

    // Name of the data entry to sponsor
    string64 dataName;
};

union SponsorshipDescriptor switch (SponsorshipType type)
{
case ACCOUNT_SPONSORSHIP:
    AccountSponsorship account;
case SIGNER_SPONSORSHIP:
    SignerSponsorship signer;
case TRUSTLINE_SPONSORSHIP:
    TrustLineSponsorship trustLine;
case OFFER_SPONSORSHIP:
    OfferSponsorship offer;
case DATA_SPONSORSHIP:
    DataSponsorship data;
};

struct SponsorshipEntry
{
    // Account that created this sponsorship
    AccountID createdBy;

    // Global ordered identifier for sponsorships
    int64 sponsorshipID;

    // Describe the ledger entries being sponsored
    SponsorshipDescriptor descriptor;

    // Reserve stored in this sponsorship
    int64 reserve;

    // reserved for future use
    union switch (int v)
    {
    case 0:
        void;
    }
    ext;
};

struct PreauthorizationEntry
{
    // Account for which the preauthorization applies
    AccountID accountID;

    // Asset for which the preauthorization applies
    Asset asset;

    // See TrustLineFlags
    uint32 flags;

    // Amount of native asset to pay the reserve
    int64 reserve;

    // reserved for future use
    union switch (int v)
    {
    case 0:
        void;
    }
    ext;
};

struct LedgerEntry
{
    uint32 lastModifiedLedgerSeq; // ledger the LedgerEntry was last changed

    union switch (LedgerEntryType type)
    {
    case ACCOUNT:
        AccountEntry account;
    case TRUSTLINE:
        TrustLineEntry trustLine;
    case OFFER:
        OfferEntry offer;
    case DATA:
        DataEntry data;
    case CLAIMABLE_BALANCE:
        ClaimableBalanceEntry claimableBalance;
    case SPONSORSHIP:
        SponsorshipEntry sponsorship;
    case PREAUTHORIZATION:
        PreauthorizationEntry preauthorization;
    }
    data;

    // reserved for future use
    union switch (int v)
    {
    case 0:
        void;
    }
    ext;
};

// list of all envelope types used in the application
// those are prefixes used when building signatures for
// the respective envelopes
enum EnvelopeType
{
    ENVELOPE_TYPE_TX_V0 = 0,
    ENVELOPE_TYPE_SCP = 1,
    ENVELOPE_TYPE_TX = 2,
    ENVELOPE_TYPE_AUTH = 3,
    ENVELOPE_TYPE_SCPVALUE = 4,
    ENVELOPE_TYPE_TX_FEE_BUMP = 5
};
}
