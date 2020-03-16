// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "herder/TransactionQueue.h"
#include "crypto/SecretKey.h"
#include "ledger/LedgerManager.h"
#include "ledger/LedgerTxn.h"
#include "main/Application.h"
#include "transactions/TransactionBridge.h"
#include "transactions/TransactionUtils.h"
#include "util/HashOfHash.h"
#include "util/XDROperators.h"

#include <algorithm>
#include <lib/util/format.h>
#include <medida/meter.h>
#include <medida/metrics_registry.h>
#include <numeric>

namespace stellar
{
const int64_t TransactionQueue::FEE_MULTIPLIER = 10;

TransactionQueue::TransactionQueue(Application& app, int pendingDepth,
                                   int banDepth, int poolLedgerMultiplier)
    : mApp(app)
    , mPendingDepth(pendingDepth)
    , mBannedTransactions(banDepth)
    , mLedgerVersion(app.getLedgerManager()
                         .getLastClosedLedgerHeader()
                         .header.ledgerVersion)
    , mPoolLedgerMultiplier(poolLedgerMultiplier)
{
    for (auto i = 0; i < pendingDepth; i++)
    {
        mSizeByAge.emplace_back(&app.getMetrics().NewCounter(
            {"herder", "pending-txs", fmt::format("age{}", i)}));
    }
}

TransactionQueue::AddResult
TransactionQueue::canAdd(TransactionFrameBasePtr tx,
                         AccountStates::iterator& stateIter,
                         Transactions::iterator& oldTxIter)
{
    if (isBanned(tx->getFullHash()))
    {
        return TransactionQueue::AddResult::ADD_STATUS_TRY_AGAIN_LATER;
    }

    if (contains(tx))
    {
        return TransactionQueue::AddResult::ADD_STATUS_DUPLICATE;
    }

    if (tx->getNumOperations() + mQueueSizeOps > maxQueueSizeOps())
    {
        ban({tx});
        return TransactionQueue::AddResult::ADD_STATUS_TRY_AGAIN_LATER;
    }

    int64_t netFee = tx->getFeeBid();
    int64_t seqNum = 0;

    stateIter = mAccountStates.find(tx->getSourceID());
    if (stateIter != mAccountStates.end() &&
        !stateIter->second.mTransactions.empty())
    {
        auto& transactions = stateIter->second.mTransactions;

        int64_t firstSeq = transactions.front()->getSeqNum();
        int64_t lastSeq = transactions.back()->getSeqNum();
        if (tx->getSeqNum() < firstSeq || tx->getSeqNum() > lastSeq + 1)
        {
            tx->getResult().result.code(txBAD_SEQ);
            return TransactionQueue::AddResult::ADD_STATUS_ERROR;
        }

        assert(tx->getSeqNum() - firstSeq <=
               static_cast<int64_t>(transactions.size()));
        oldTxIter = transactions.begin() + (tx->getSeqNum() - firstSeq);
        assert(oldTxIter == transactions.end() ||
               (*oldTxIter)->getSeqNum() == tx->getSeqNum());

        if (oldTxIter != transactions.end())
        {
            int64_t oldFee = (*oldTxIter)->getFeeBid();
            if (tx->getFeeBid() < FEE_MULTIPLIER * oldFee)
            {
                tx->getResult().result.code(txINSUFFICIENT_FEE);
                return TransactionQueue::AddResult::ADD_STATUS_ERROR;
            }

            if ((*oldTxIter)->getFeeSourceID() == tx->getFeeSourceID())
            {
                netFee -= oldFee;
            }
        }

        seqNum = tx->getSeqNum() - 1;
    }

    LedgerTxn ltx(mApp.getLedgerTxnRoot());
    if (!tx->checkValid(ltx, seqNum))
    {
        return TransactionQueue::AddResult::ADD_STATUS_ERROR;
    }

    // Note: stateIter corresponds to getSourceID() which is not necessarily
    // the same as getFeeSourceID()
    auto feeSource = stellar::loadAccount(ltx, tx->getFeeSourceID());
    auto feeStateIter = mAccountStates.find(tx->getFeeSourceID());
    int64_t totalFees = feeStateIter == mAccountStates.end()
                            ? 0
                            : feeStateIter->second.mTotalFees;
    if (getAvailableBalance(ltx.loadHeader(), feeSource) - netFee < totalFees)
    {
        tx->getResult().result.code(txINSUFFICIENT_BALANCE);
        return TransactionQueue::AddResult::ADD_STATUS_ERROR;
    }

    return TransactionQueue::AddResult::ADD_STATUS_PENDING;
}

void
TransactionQueue::releaseFeeMaybeEraseAccountState(TransactionFrameBasePtr tx)
{
    auto iter = mAccountStates.find(tx->getFeeSourceID());
    assert(iter != mAccountStates.end() &&
           iter->second.mTotalFees >= tx->getFeeBid());

    iter->second.mTotalFees -= tx->getFeeBid();
    if (iter->second.mTransactions.empty())
    {
        if (iter->second.mTotalFees == 0)
        {
            mAccountStates.erase(iter);
        }
    }
}

TransactionQueue::AddResult
TransactionQueue::tryAdd(TransactionFrameBasePtr tx)
{
    AccountStates::iterator stateIter;
    Transactions::iterator oldTxIter;
    auto const res = canAdd(tx, stateIter, oldTxIter);
    if (res != TransactionQueue::AddResult::ADD_STATUS_PENDING)
    {
        return res;
    }

    if (stateIter == mAccountStates.end())
    {
        stateIter =
            mAccountStates.emplace(tx->getSourceID(), AccountState{}).first;
        oldTxIter = stateIter->second.mTransactions.end();
    }

    if (oldTxIter != stateIter->second.mTransactions.end())
    {
        releaseFeeMaybeEraseAccountState(*oldTxIter);
        stateIter->second.mQueueSizeOps -= (*oldTxIter)->getNumOperations();
        mQueueSizeOps -= (*oldTxIter)->getNumOperations();
        *oldTxIter = tx;
    }
    else
    {
        stateIter->second.mTransactions.emplace_back(tx);
        mSizeByAge[stateIter->second.mAge]->inc();
    }
    stateIter->second.mQueueSizeOps += tx->getNumOperations();
    mQueueSizeOps += tx->getNumOperations();
    mAccountStates[tx->getFeeSourceID()].mTotalFees += tx->getFeeBid();

    return res;
}

void
TransactionQueue::removeAndReset(TransactionQueue::Transactions const& dropTxs)
{
    for (auto const& tx : dropTxs)
    {
        auto extracted = extract(tx, true);
        if (extracted.first != std::end(mAccountStates))
        {
            extracted.first->second.mAge = 0;
        }
    }
}

void
TransactionQueue::ban(TransactionQueue::Transactions const& dropTxs)
{
    auto& bannedFront = mBannedTransactions.front();
    for (auto const& tx : dropTxs)
    {
        auto extractResult = extract(tx, false);
        if (extractResult.second.empty())
        {
            // tx was not in the queue
            bannedFront.insert(tx->getFullHash());
        }
        else
        {
            // tx was in the queue, and may have caused other transactions to
            // get dropped as well
            for (auto const& extracted : extractResult.second)
            {
                bannedFront.insert(extracted->getFullHash());
            }
        }
    }
}

bool
TransactionQueue::contains(TransactionFrameBasePtr tx)
{
    return find(tx).first != std::end(mAccountStates);
}

TransactionQueue::FindResult
TransactionQueue::find(TransactionFrameBasePtr const& tx)
{
    auto const& acc = tx->getSourceID();
    auto accIt = mAccountStates.find(acc);
    if (accIt == std::end(mAccountStates))
    {
        return {std::end(mAccountStates), {}};
    }

    auto& txs = accIt->second.mTransactions;
    auto txIt =
        std::find_if(std::begin(txs), std::end(txs), [&](auto const& t) {
            return tx->getSeqNum() == t->getSeqNum();
        });
    if (txIt == std::end(txs))
    {
        return {std::end(mAccountStates), {}};
    }

    if ((*txIt)->getFullHash() != tx->getFullHash())
    {
        return {std::end(mAccountStates), {}};
    }

    return {accIt, txIt};
}

TransactionQueue::ExtractResult
TransactionQueue::extract(TransactionFrameBasePtr const& tx, bool keepBacklog)
{
    std::vector<TransactionFrameBasePtr> removedTxs;

    // Use a scope here to prevent iterator use after invalidation
    {
        auto it = find(tx);
        if (it.first == mAccountStates.end())
        {
            return {std::end(mAccountStates), {}};
        }

        auto txIt = it.second;
        auto txRemoveEnd = txIt + 1;
        if (!keepBacklog)
        {
            // remove everything passed tx
            txRemoveEnd = it.first->second.mTransactions.end();
        }

        std::move(txIt, txRemoveEnd, std::back_inserter(removedTxs));
        it.first->second.mTransactions.erase(txIt, txRemoveEnd);

        mSizeByAge[it.first->second.mAge]->dec(removedTxs.size());
    }

    for (auto const& removedTx : removedTxs)
    {
        mAccountStates[removedTx->getSourceID()].mQueueSizeOps -=
            removedTx->getNumOperations();
        mQueueSizeOps -= removedTx->getNumOperations();
        releaseFeeMaybeEraseAccountState(removedTx);
    }

    // tx->getSourceID() will only be in mAccountStates if it has pending
    // transactions or if it is the fee source for a transaction for which it is
    // not the sequence number source
    auto accIt = mAccountStates.find(tx->getSourceID());
    if (accIt != mAccountStates.end() && accIt->second.mTransactions.empty())
    {
        if (accIt->second.mTotalFees == 0)
        {
            mAccountStates.erase(accIt);
            accIt = mAccountStates.end();
        }
        else
        {
            accIt->second.mAge = 0;
        }
    }

    return {accIt, std::move(removedTxs)};
}

TransactionQueue::AccountTxQueueInfo
TransactionQueue::getAccountTransactionQueueInfo(
    AccountID const& accountID) const
{
    auto i = mAccountStates.find(accountID);
    if (i == std::end(mAccountStates))
    {
        return {0, 0, 0, 0};
    }

    auto const& txs = i->second.mTransactions;
    auto seqNum = txs.empty() ? 0 : txs.back()->getSeqNum();
    return {seqNum, i->second.mTotalFees, i->second.mQueueSizeOps,
            i->second.mAge};
}

void
TransactionQueue::shift()
{
    mBannedTransactions.pop_back();
    mBannedTransactions.emplace_front();

    auto sizes = std::vector<int64_t>{};
    sizes.resize(mPendingDepth);

    auto& bannedFront = mBannedTransactions.front();
    auto end = std::end(mAccountStates);
    auto it = std::begin(mAccountStates);
    while (it != end)
    {
        // If mTransactions is empty then mAge is always 0. This can occur if an
        // account is the fee-source for at least one transaction but not the
        // sequence-number-source for any transaction in the TransactionQueue.
        if (!it->second.mTransactions.empty())
        {
            ++it->second.mAge;
        }

        if (mPendingDepth == it->second.mAge)
        {
            for (auto const& toBan : it->second.mTransactions)
            {
                // This never invalidates it because
                //     !it->second.mTransactions.empty()
                // otherwise we couldn't have reached this line.
                releaseFeeMaybeEraseAccountState(toBan);
                bannedFront.insert(toBan->getFullHash());
            }
            mQueueSizeOps -= it->second.mQueueSizeOps;
            it->second.mQueueSizeOps = 0;

            it->second.mTransactions.clear();
            if (it->second.mTotalFees == 0)
            {
                it = mAccountStates.erase(it);
            }
            else
            {
                it->second.mAge = 0;
            }
        }
        else
        {
            sizes[it->second.mAge] +=
                static_cast<int64_t>(it->second.mTransactions.size());
            ++it;
        }
    }

    for (auto i = 0; i < sizes.size(); i++)
    {
        mSizeByAge[i]->set_count(sizes[i]);
    }
}

int
TransactionQueue::countBanned(int index) const
{
    return static_cast<int>(mBannedTransactions[index].size());
}

bool
TransactionQueue::isBanned(Hash const& hash) const
{
    return std::any_of(
        std::begin(mBannedTransactions), std::end(mBannedTransactions),
        [&](std::unordered_set<Hash> const& transactions) {
            return transactions.find(hash) != std::end(transactions);
        });
}

std::shared_ptr<TxSetFrame>
TransactionQueue::toTxSet(LedgerHeaderHistoryEntry const& lcl) const
{
    auto result = std::make_shared<TxSetFrame>(lcl.hash);

    uint32_t const nextLedgerSeq = lcl.header.ledgerSeq + 1;
    int64_t const startingSeq = getStartingSequenceNumber(nextLedgerSeq);
    for (auto const& m : mAccountStates)
    {
        for (auto const& tx : m.second.mTransactions)
        {
            result->add(tx);
            // This condition implements the following constraint: there may be
            // any number of transactions for a given source account, but all
            // transactions must satisfy one of the following mutually exclusive
            // conditions
            // - sequence number <= startingSeq - 1
            // - sequence number >= startingSeq
            if (tx->getSeqNum() == startingSeq - 1)
            {
                break;
            }
        }
    }

    return result;
}

std::vector<TransactionQueue::ReplacedTransaction>
TransactionQueue::maybeVersionUpgraded()
{
    std::vector<ReplacedTransaction> res;

    auto const& lcl = mApp.getLedgerManager().getLastClosedLedgerHeader();
    if (mLedgerVersion < 13 && lcl.header.ledgerVersion >= 13)
    {
        for (auto& banned : mBannedTransactions)
        {
            banned.clear();
        }

        for (auto& kv : mAccountStates)
        {
            for (auto& txFrame : kv.second.mTransactions)
            {
                auto oldTxFrame = txFrame;
                auto envV1 = txbridge::convertToV1(txFrame->getEnvelope());
                txFrame = TransactionFrame::makeTransactionFromWire(
                    mApp.getNetworkID(), envV1);
                res.emplace_back(ReplacedTransaction{oldTxFrame, txFrame});
            }
        }
    }
    mLedgerVersion = lcl.header.ledgerVersion;

    return res;
}

bool
operator==(TransactionQueue::AccountTxQueueInfo const& x,
           TransactionQueue::AccountTxQueueInfo const& y)
{
    return x.mMaxSeq == y.mMaxSeq && x.mTotalFees == y.mTotalFees &&
           x.mQueueSizeOps == y.mQueueSizeOps;
}

size_t
TransactionQueue::maxQueueSizeOps() const
{
    size_t maxOpsLedger = mApp.getLedgerManager().getLastMaxTxSetSizeOps();
    maxOpsLedger *= mPoolLedgerMultiplier;
    return maxOpsLedger;
}
}
