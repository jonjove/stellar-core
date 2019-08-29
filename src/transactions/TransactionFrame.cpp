// Copyright 2014 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "util/asio.h"
#include "TransactionFrame.h"
#include "OperationFrame.h"
#include "crypto/Hex.h"
#include "crypto/SHA.h"
#include "crypto/SignerKey.h"
#include "invariant/InvariantManager.h"
#include "ledger/LedgerTxn.h"
#include "ledger/LedgerTxnEntry.h"
#include "ledger/LedgerTxnHeader.h"
#include "main/Application.h"
#include "transactions/SignatureChecker.h"
#include "transactions/SignatureUtils.h"
#include "transactions/TransactionUtils.h"
#include "util/Algoritm.h"
#include "util/Logging.h"
#include "util/XDROperators.h"
#include "xdrpp/marshal.h"
#include <string>

#include "medida/meter.h"
#include "medida/metrics_registry.h"

#include <algorithm>
#include <numeric>

namespace stellar
{

using namespace std;

static Transaction
convertToTransaction(TransactionV0 const& tx)
{
    Transaction res;
    res.sourceAccount.type(PUBLIC_KEY_TYPE_ED25519);
    res.sourceAccount.ed25519() = tx.sourceAccountEd25519;
    res.fee = tx.fee;
    res.seqNum = tx.seqNum;
    res.timeBounds = tx.timeBounds;
    res.memo = tx.memo;
    res.operations = tx.operations;
    return res;
}

TransactionFrame::TransactionFrame(Hash const& networkID,
                                   TransactionEnvelope const& envelope,
                                   bool chargeFee)
    : mChargeFee(chargeFee), mEnvelope(envelope), mNetworkID(networkID)
{
}

Hash const&
TransactionFrame::getFullHash() const
{
    if (isZero(mFullHash))
    {
        mFullHash = sha256(xdr::xdr_to_opaque(mEnvelope));
    }
    return (mFullHash);
}

Hash const&
TransactionFrame::getInnerHash() const
{
    return getFullHash();
}

Hash const&
TransactionFrame::getContentsHash() const
{
    if (isZero(mContentsHash))
    {
        mContentsHash =
            sha256(xdr::xdr_to_opaque(mNetworkID, ENVELOPE_TYPE_TX,
                                      convertToTransaction(mEnvelope.v0().tx)));
    }
    return (mContentsHash);
}

void
TransactionFrame::clearCached()
{
    Hash zero;
    mContentsHash = zero;
    mFullHash = zero;
}

TransactionResultPair
TransactionFrame::getResultPair() const
{
    TransactionResultPair trp;
    trp.transactionHash = getContentsHash();
    trp.result = mResult;
    return trp;
}

TransactionEnvelope const&
TransactionFrame::getEnvelope() const
{
    return mEnvelope;
}

TransactionEnvelope&
TransactionFrame::getEnvelope()
{
    return mEnvelope;
}

int64_t
TransactionFrame::getFeeBid() const
{
    return mEnvelope.v0().tx.fee;
}

int64_t
TransactionFrame::getMinFee(LedgerHeader const& header) const
{
    return ((int64_t)header.baseFee) *
           std::max<int64_t>(1, getOperationCountForValidation());
}

int64_t
TransactionFrame::getFee(LedgerHeader const& header, int64_t baseFee) const
{
    if (!mChargeFee)
    {
        return 0;
    }

    if (header.ledgerVersion < 11)
    {
        return getFeeBid();
    }
    else
    {
        int64_t adjustedFee =
            baseFee * std::max<int64_t>(1, getOperationCountForValidation());
        return std::min<int64_t>(getFeeBid(), adjustedFee);
    }
}

void
TransactionFrame::addSignature(SecretKey const& secretKey)
{
    clearCached();
    auto sig = SignatureUtils::sign(secretKey, getContentsHash());
    addSignature(sig);
}

void
TransactionFrame::addSignature(DecoratedSignature const& signature)
{
    mEnvelope.v0().signatures.push_back(signature);
    std::sort(mEnvelope.v0().signatures.begin(),
              mEnvelope.v0().signatures.end(), signatureCompare);
}

bool
TransactionFrame::checkSignature(SignatureChecker& signatureChecker,
                                 LedgerTxnEntry const& account,
                                 int32_t neededWeight)
{
    auto& acc = account.current().data.account();
    std::vector<Signer> signers;
    if (acc.thresholds[0])
    {
        auto signerKey = KeyUtils::convertKey<SignerKey>(acc.accountID);
        signers.push_back(Signer(signerKey, acc.thresholds[0]));
    }
    signers.insert(signers.end(), acc.signers.begin(), acc.signers.end());

    return signatureChecker.checkSignature(acc.accountID, signers,
                                           neededWeight);
}

bool
TransactionFrame::checkSignatureNoAccount(SignatureChecker& signatureChecker,
                                          AccountID const& accountID)
{
    std::vector<Signer> signers;
    auto signerKey = KeyUtils::convertKey<SignerKey>(accountID);
    signers.push_back(Signer(signerKey, 1));
    return signatureChecker.checkSignature(accountID, signers, 0);
}

LedgerTxnEntry
TransactionFrame::loadSourceAccount(AbstractLedgerTxn& ltx,
                                    LedgerTxnHeader const& header)
{
    auto res = loadAccount(ltx, header, getSourceID());
    if (header.current().ledgerVersion < 8)
    {
        // this is buggy caching that existed in old versions of the protocol
        if (res)
        {
            auto newest = ltx.getNewestVersion(LedgerEntryKey(res.current()));
            mCachedAccount = newest;
        }
        else
        {
            mCachedAccount.reset();
        }
    }
    return res;
}

LedgerTxnEntry
TransactionFrame::loadAccount(AbstractLedgerTxn& ltx,
                              LedgerTxnHeader const& header,
                              AccountID const& accountID)
{
    if (header.current().ledgerVersion < 8 && mCachedAccount &&
        mCachedAccount->data.account().accountID == accountID)
    {
        // this is buggy caching that existed in old versions of the protocol
        auto res = stellar::loadAccount(ltx, accountID);
        if (res)
        {
            res.current() = *mCachedAccount;
        }
        else
        {
            res = ltx.create(*mCachedAccount);
        }

        auto newest = ltx.getNewestVersion(LedgerEntryKey(res.current()));
        mCachedAccount = newest;
        return res;
    }
    else
    {
        return stellar::loadAccount(ltx, accountID);
    }
}

std::shared_ptr<OperationFrame>
TransactionFrame::makeOperation(Operation const& op, OperationResult& res,
                                size_t index)
{
    return OperationFrame::makeHelper(op, res, *this);
}

void
TransactionFrame::resetResults(LedgerHeader const& header, int64_t baseFee)
{
    // pre-allocates the results for all operations
    getResult().result.code(txSUCCESS);
    getResult().result.results().resize(
        (uint32_t)mEnvelope.v0().tx.operations.size());

    mOperations.clear();

    // bind operations to the results
    for (size_t i = 0; i < mEnvelope.v0().tx.operations.size(); i++)
    {
        mOperations.push_back(makeOperation(mEnvelope.v0().tx.operations[i],
                                            getResult().result.results()[i],
                                            i));
    }

    // feeCharged is updated accordingly to represent the cost of the
    // transaction regardless of the failure modes.
    getResult().feeCharged = getFee(header, baseFee);
}

bool
TransactionFrame::isTooEarly(LedgerTxnHeader const& header) const
{
    if (mEnvelope.v0().tx.timeBounds)
    {
        uint64 closeTime = header.current().scpValue.closeTime;
        return mEnvelope.v0().tx.timeBounds->minTime > closeTime;
    }
    return false;
}

bool
TransactionFrame::isTooLate(LedgerTxnHeader const& header) const
{
    if (mEnvelope.v0().tx.timeBounds)
    {
        uint64 closeTime = header.current().scpValue.closeTime;
        return mEnvelope.v0().tx.timeBounds->maxTime &&
               (mEnvelope.v0().tx.timeBounds->maxTime < closeTime);
    }
    return false;
}

bool
TransactionFrame::commonValidPreSeqNum(AbstractLedgerTxn& ltx, bool forApply)
{
    // this function does validations that are independent of the account state
    //    (stay true regardless of other side effects)

    auto header = ltx.loadHeader();
    if (header.current().ledgerVersion >= 12 &&
        !std::is_sorted(mEnvelope.v0().signatures.begin(),
                        mEnvelope.v0().signatures.end(), signatureCompare))
    {
        getResult().result.code(txNOT_NORMALIZED);
        return false;
    }

    if (mOperations.size() == 0)
    {
        getResult().result.code(txMISSING_OPERATION);
        return false;
    }

    if (isTooEarly(header))
    {
        getResult().result.code(txTOO_EARLY);
        return false;
    }
    if (isTooLate(header))
    {
        getResult().result.code(txTOO_LATE);
        return false;
    }

    if (mChargeFee && getFeeBid() < getMinFee(header.current()))
    {
        getResult().result.code(txINSUFFICIENT_FEE);
        return false;
    }

    if (!loadSourceAccount(ltx, header))
    {
        getResult().result.code(txNO_ACCOUNT);
        return false;
    }

    return true;
}

void
TransactionFrame::processSeqNum(AbstractLedgerTxn& ltx)
{
    auto header = ltx.loadHeader();
    if (header.current().ledgerVersion >= 10)
    {
        auto sourceAccount = loadSourceAccount(ltx, header);
        if (sourceAccount.current().data.account().seqNum > getSeqNum())
        {
            throw std::runtime_error("unexpected sequence number");
        }
        sourceAccount.current().data.account().seqNum = getSeqNum();
    }
}

bool
TransactionFrame::processSignatures(SignatureChecker& signatureChecker,
                                    AbstractLedgerTxn& ltxOuter)
{
    auto allOpsValid = true;
    {
        LedgerTxn ltx(ltxOuter);
        if (ltx.loadHeader().current().ledgerVersion < 10)
        {
            return true;
        }

        for (auto& op : mOperations)
        {
            if (!op->checkSignature(signatureChecker, ltx, false))
            {
                allOpsValid = false;
            }
        }
    }

    removeUsedOneTimeSignerKeys(signatureChecker, ltxOuter);

    if (!allOpsValid)
    {
        markResultFailed();
        return false;
    }

    if (!signatureChecker.checkAllSignaturesUsed())
    {
        getResult().result.code(txBAD_AUTH_EXTRA);
        return false;
    }

    return true;
}

bool
TransactionFrame::isBadSeq(int64_t seqNum) const
{
    return seqNum == INT64_MAX || seqNum + 1 != getSeqNum();
}

TransactionFrame::ValidationType
TransactionFrame::commonValid(SignatureChecker& signatureChecker,
                              AbstractLedgerTxn& ltxOuter,
                              SequenceNumber current, bool applying)
{
    LedgerTxn ltx(ltxOuter);
    ValidationType res = ValidationType::kInvalid;

    if (!commonValidPreSeqNum(ltx, applying))
    {
        return res;
    }

    auto header = ltx.loadHeader();
    auto sourceAccount = loadSourceAccount(ltx, header);

    // in older versions, the account's sequence number is updated when taking
    // fees
    if (header.current().ledgerVersion >= 10 || !applying)
    {
        if (current == 0)
        {
            current = sourceAccount.current().data.account().seqNum;
        }
        if (isBadSeq(current))
        {
            getResult().result.code(txBAD_SEQ);
            return res;
        }
    }

    res = ValidationType::kInvalidUpdateSeqNum;

    if (!checkSignature(
            signatureChecker, sourceAccount,
            sourceAccount.current().data.account().thresholds[THRESHOLD_LOW]))
    {
        getResult().result.code(txBAD_AUTH);
        return res;
    }

    res = ValidationType::kInvalidPostAuth;

    // if we are in applying mode fee was already deduced from signing account
    // balance, if not, we need to check if after that deduction this account
    // will still have minimum balance
    int64_t feeToPay =
        (applying && (header.current().ledgerVersion > 8)) ? 0 : getFeeBid();
    // don't let the account go below the reserve after accounting for
    // liabilities
    if (mChargeFee && getAvailableBalance(header, sourceAccount) < feeToPay)
    {
        getResult().result.code(txINSUFFICIENT_BALANCE);
        return res;
    }

    return ValidationType::kFullyValid;
}

void
TransactionFrame::insertLedgerKeysToPrefetch(
    std::unordered_set<LedgerKey>& keys) const
{
    for (auto const& op : mOperations)
    {
        if (!(getSourceID() == op->getSourceID()))
        {
            keys.emplace(accountKey(op->getSourceID()));
        }
        op->insertLedgerKeysToPrefetch(keys);
    }
}

void
TransactionFrame::processFeeSeqNum(AbstractLedgerTxn& ltx, int64_t baseFee)
{
    mCachedAccount.reset();

    auto header = ltx.loadHeader();
    resetResults(header.current(), baseFee);

    auto sourceAccount = loadSourceAccount(ltx, header);
    if (!sourceAccount)
    {
        throw std::runtime_error("Unexpected database state");
    }
    auto& acc = sourceAccount.current().data.account();

    int64_t& fee = getResult().feeCharged;
    if (fee > 0)
    {
        fee = std::min(acc.balance, fee);
        // Note: TransactionUtil addBalance checks that reserve plus liabilities
        // are respected. In this case, we allow it to fall below that since it
        // will be caught later in commonValid.
        stellar::addBalance(acc.balance, -fee);
        header.current().feePool += fee;
    }
    // in v10 we update sequence numbers during apply
    if (header.current().ledgerVersion <= 9)
    {
        if (acc.seqNum + 1 != getSeqNum())
        {
            // this should not happen as the transaction set is sanitized for
            // sequence numbers
            throw std::runtime_error("Unexpected account state");
        }
        acc.seqNum = getSeqNum();
    }
}

void
TransactionFrame::removeUsedOneTimeSignerKeys(
    SignatureChecker& signatureChecker, AbstractLedgerTxn& ltx)
{
    for (auto const& usedAccount : signatureChecker.usedOneTimeSignerKeys())
    {
        removeUsedOneTimeSignerKeys(ltx, usedAccount.first, usedAccount.second);
    }
}

void
TransactionFrame::removeUsedOneTimeSignerKeys(
    AbstractLedgerTxn& ltx, AccountID const& accountID,
    std::set<SignerKey> const& keys) const
{
    auto account = stellar::loadAccount(ltx, accountID);
    if (!account)
    {
        return; // probably account was removed due to merge operation
    }

    auto header = ltx.loadHeader();
    auto changed = std::accumulate(
        std::begin(keys), std::end(keys), false,
        [&](bool r, const SignerKey& signerKey) {
            return r || removeAccountSigner(header, account, signerKey);
        });

    if (changed)
    {
        normalizeSigners(account);
    }
}

bool
TransactionFrame::removeAccountSigner(LedgerTxnHeader const& header,
                                      LedgerTxnEntry& account,
                                      SignerKey const& signerKey) const
{
    auto& acc = account.current().data.account();
    auto it = std::find_if(
        std::begin(acc.signers), std::end(acc.signers),
        [&signerKey](Signer const& signer) { return signer.key == signerKey; });
    if (it != std::end(acc.signers))
    {
        auto removed = stellar::addNumEntries(header, account, -1);
        assert(removed == AddSubentryResult::SUCCESS);
        acc.signers.erase(it);
        return true;
    }

    return false;
}

bool
TransactionFrame::checkValid(AbstractLedgerTxn& ltxOuter,
                             SequenceNumber current)
{
    mCachedAccount.reset();

    LedgerTxn ltx(ltxOuter);
    auto minBaseFee = ltx.loadHeader().current().baseFee;
    resetResults(ltx.loadHeader().current(), minBaseFee);

    SignatureChecker signatureChecker{ltx.loadHeader().current().ledgerVersion,
                                      getContentsHash(),
                                      mEnvelope.v0().signatures};
    bool res = commonValid(signatureChecker, ltx, current, false) ==
               ValidationType::kFullyValid;
    if (res)
    {
        for (auto& op : mOperations)
        {
            if (!op->checkValid(signatureChecker, ltx, false))
            {
                // it's OK to just fast fail here and not try to call
                // checkValid on all operations as the resulting object
                // is only used by applications
                markResultFailed();
                return false;
            }
        }

        if (!signatureChecker.checkAllSignaturesUsed())
        {
            res = false;
            getResult().result.code(txBAD_AUTH_EXTRA);
        }
    }
    return res;
}

void
TransactionFrame::markResultFailed()
{
    // changing "code" causes the xdr struct to be deleted/re-created
    // As we want to preserve the results, we save them inside a temp object
    // Also, note that because we're using move operators
    // mOperations are still valid (they have pointers to the individual
    // results elements)
    xdr::xvector<OperationResult> t(std::move(getResult().result.results()));
    getResult().result.code(txFAILED);
    getResult().result.results() = std::move(t);

    // sanity check in case some implementations decide
    // to not implement std::move properly
    auto const& allResults = getResult().result.results();
    assert(allResults.size() == mOperations.size());
    for (size_t i = 0; i < mOperations.size(); i++)
    {
        assert(&mOperations[i]->getResult() == &allResults[i]);
    }
}

bool
TransactionFrame::apply(Application& app, AbstractLedgerTxn& ltx)
{
    TransactionMeta tm(1);
    return apply(app, ltx, tm.v1());
}

bool
TransactionFrame::applyOperations(SignatureChecker& signatureChecker,
                                  Application& app, AbstractLedgerTxn& ltx,
                                  TransactionMetaV1& meta)
{
    bool errorEncountered = false;

    // shield outer scope of any side effects with LedgerTxn
    LedgerTxn ltxTx(ltx);
    auto& opTimer = app.getMetrics().NewTimer({"ledger", "operation", "apply"});
    for (auto& op : mOperations)
    {
        auto time = opTimer.TimeScope();
        LedgerTxn ltxOp(ltxTx);
        bool txRes = op->apply(signatureChecker, ltxOp);

        if (!txRes)
        {
            errorEncountered = true;
        }
        if (!errorEncountered)
        {
            app.getInvariantManager().checkOnOperationApply(
                op->getOperation(), op->getResult(), ltxOp.getDelta());
        }
        meta.operations.emplace_back(ltxOp.getChanges());
        ltxOp.commit();
    }

    if (!errorEncountered)
    {
        if (ltxTx.loadHeader().current().ledgerVersion < 10)
        {
            if (!signatureChecker.checkAllSignaturesUsed())
            {
                getResult().result.code(txBAD_AUTH_EXTRA);
                // this should never happen: malformed transaction should
                // not be accepted by nodes
                return false;
            }

            // if an error occurred, it is responsibility of account's owner
            // to remove that signer
            removeUsedOneTimeSignerKeys(signatureChecker, ltxTx);
        }

        ltxTx.commit();
    }

    if (errorEncountered)
    {
        meta.operations.clear();
        markResultFailed();
    }
    return !errorEncountered;
}

bool
TransactionFrame::apply(Application& app, AbstractLedgerTxn& ltx,
                        TransactionMetaV1& meta)
{
    mCachedAccount.reset();
    SignatureChecker signatureChecker{ltx.loadHeader().current().ledgerVersion,
                                      getContentsHash(),
                                      mEnvelope.v0().signatures};

    bool valid = false;
    {
        LedgerTxn ltxTx(ltx);
        // when applying, a failure during tx validation means that
        // we'll skip trying to apply operations but we'll still
        // process the sequence number if needed
        auto cv = commonValid(signatureChecker, ltxTx, 0, true);
        if (cv >= ValidationType::kInvalidUpdateSeqNum)
        {
            processSeqNum(ltxTx);
        }
        auto signaturesValid = cv >= (ValidationType::kInvalidPostAuth) &&
                               processSignatures(signatureChecker, ltxTx);
        meta.txChanges = ltxTx.getChanges();
        ltxTx.commit();
        valid = signaturesValid && (cv == ValidationType::kFullyValid);
    }
    return valid && applyOperations(signatureChecker, app, ltx, meta);
}

StellarMessage
TransactionFrame::toStellarMessage() const
{
    StellarMessage msg;
    msg.type(TRANSACTION);
    msg.transaction() = mEnvelope;
    return msg;
}

std::vector<TransactionFrameBasePtr>
TransactionFrame::transactionsToApply()
{
    return {shared_from_this()};
}
}
