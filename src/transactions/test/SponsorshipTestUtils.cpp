// Copyright 2020 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "transactions/test/SponsorshipTestUtils.h"
#include "ledger/LedgerManager.h"
#include "ledger/LedgerTxn.h"
#include "ledger/LedgerTxnEntry.h"
#include "ledger/LedgerTxnHeader.h"
#include "lib/catch.hpp"
#include "main/Application.h"
#include "test/TestAccount.h"
#include "test/TxTests.h"
#include "test/test.h"
#include "transactions/SignatureUtils.h"
#include "transactions/TransactionUtils.h"

using namespace stellar;
using namespace stellar::txtest;

static void
sign(Hash const& networkID, SecretKey key, TransactionV1Envelope& env)
{
    env.signatures.emplace_back(SignatureUtils::sign(
        key, sha256(xdr::xdr_to_opaque(networkID, ENVELOPE_TYPE_TX, env.tx))));
}

static TransactionEnvelope
envelopeFromOps(Hash const& networkID, TestAccount& source,
                std::vector<Operation> const& ops,
                std::vector<SecretKey> const& opKeys)
{
    TransactionEnvelope tx(ENVELOPE_TYPE_TX);
    tx.v1().tx.sourceAccount = toMuxedAccount(source);
    tx.v1().tx.fee = 100 * ops.size();
    tx.v1().tx.seqNum = source.nextSequenceNumber();
    std::copy(ops.begin(), ops.end(),
              std::back_inserter(tx.v1().tx.operations));

    sign(networkID, source, tx.v1());
    for (auto const& opKey : opKeys)
    {
        sign(networkID, opKey, tx.v1());
    }
    return tx;
}

static TransactionFrameBasePtr
transactionFrameFromOps(Hash const& networkID, TestAccount& source,
                        std::vector<Operation> const& ops,
                        std::vector<SecretKey> const& opKeys)
{
    return TransactionFrameBase::makeTransactionFromWire(
        networkID, envelopeFromOps(networkID, source, ops, opKeys));
}

static OperationResult
getOperationResult(TransactionFrameBasePtr& tx, size_t i)
{
    return tx->getResult().result.results()[i];
}

namespace stellar
{

void
checkSponsorship(AbstractLedgerTxn& ltx, LedgerKey const& lk, int leExt,
                 AccountID const* sponsoringID)
{
    auto ltxe = ltx.load(lk);
    auto const& le = ltxe.current();

    REQUIRE(le.ext.v() == leExt);
    if (leExt == 1)
    {
        REQUIRE(le.ext.v() == 1);
        if (!sponsoringID)
        {
            REQUIRE(!le.ext.v1().sponsoringID);
        }
        else
        {
            REQUIRE(le.ext.v1().sponsoringID);
            REQUIRE(*le.ext.v1().sponsoringID == *sponsoringID);
        }
    }
}

void
checkSponsorship(AbstractLedgerTxn& ltx, AccountID const& accountID,
                 SignerKey const& signerKey, int aeExt,
                 AccountID const* sponsoringID)
{
    auto ltxe = loadAccount(ltx, accountID);
    auto const& ae = ltxe.current().data.account();

    auto signerIt =
        std::find_if(ae.signers.begin(), ae.signers.end(),
                     [&](auto const& s) { return s.key == signerKey; });
    REQUIRE(signerIt != ae.signers.end());
    size_t n = signerIt - ae.signers.begin();

    switch (aeExt)
    {
    case 0:
        REQUIRE(ae.ext.v() == 0);
        break;
    case 1:
        REQUIRE(ae.ext.v() == 1);
        REQUIRE(ae.ext.v1().ext.v() == 0);
        break;
    case 2:
        REQUIRE(ae.ext.v() == 1);
        REQUIRE(ae.ext.v1().ext.v() == 2);
        if (sponsoringID)
        {
            REQUIRE(ae.ext.v1().ext.v2().signerSponsoringIDs.at(n));
            REQUIRE(*ae.ext.v1().ext.v2().signerSponsoringIDs.at(n) ==
                    *sponsoringID);
        }
        else
        {
            REQUIRE(!ae.ext.v1().ext.v2().signerSponsoringIDs.at(n));
        }
        break;
    }
}

void
checkSponsorship(AbstractLedgerTxn& ltx, AccountID const& acc, int leExt,
                 AccountID const* sponsoringID, uint32_t numSubEntries,
                 int aeExt, uint32_t numSponsoring, uint32_t numSponsored)
{
    checkSponsorship(ltx, accountKey(acc), leExt, sponsoringID);

    auto le = loadAccount(ltx, acc);
    auto const& ae = le.current().data.account();
    REQUIRE(ae.numSubEntries == numSubEntries);
    switch (aeExt)
    {
    case 0:
        REQUIRE(ae.ext.v() == 0);
        break;
    case 1:
        REQUIRE(ae.ext.v() == 1);
        REQUIRE(ae.ext.v1().ext.v() == 0);
        break;
    case 2:
        REQUIRE(ae.ext.v() == 1);
        REQUIRE(ae.ext.v1().ext.v() == 2);
        REQUIRE(ae.ext.v1().ext.v2().numSponsoring == numSponsoring);
        REQUIRE(ae.ext.v1().ext.v2().numSponsored == numSponsored);
        break;
    }
}

void
createSponsoredEntryButSponsorHasInsufficientBalance(
    Application& app, TestAccount& sponsoringAcc, TestAccount& sponsoredAcc,
    Operation const& op, std::function<bool(OperationResult const&)> check)
{
    SECTION("create sponsored entry but sponsor has insufficient balance")
    {
        for_versions_from(14, app, [&] {
            auto root = TestAccount::createRoot(app);
            auto tx = transactionFrameFromOps(
                app.getNetworkID(), root,
                {sponsoringAcc.op(sponsorFutureReserves(sponsoredAcc)),
                 sponsoredAcc.op(op),
                 sponsoredAcc.op(confirmAndClearSponsor())},
                {sponsoringAcc.getSecretKey(), sponsoredAcc.getSecretKey()});

            LedgerTxn ltx(app.getLedgerTxnRoot());
            TransactionMeta txm(2);
            REQUIRE(tx->checkValid(ltx, 0, 0, 0));
            REQUIRE(!tx->apply(app, ltx, txm));
            REQUIRE(check(getOperationResult(tx, 1)));
            ltx.commit();
        });
    }
}

static void
createModifyAndRemoveSponsoredEntry(Application& app, TestAccount& sponsoredAcc,
                                    Operation const& opCreate,
                                    Operation const& opModify1,
                                    Operation const& opModify2,
                                    Operation const& opRemove,
                                    RevokeSponsorshipOp const& uso)
{
    SECTION("create, modify, and remove sponsored entry")
    {
        for_versions_from(14, app, [&] {
            uint32_t nse;
            {
                LedgerTxn ltx(app.getLedgerTxnRoot());
                auto ltxe = loadAccount(ltx, sponsoredAcc);
                nse = ltxe.current().data.account().numSubEntries;
            }

            int64_t txfee = app.getLedgerManager().getLastTxFee();
            int64_t minBalance0 = app.getLedgerManager().getLastMinBalance(0);
            auto root = TestAccount::createRoot(app);
            auto a2 = root.create("cmarseAcc1", minBalance0 + txfee);

            auto tx = transactionFrameFromOps(
                app.getNetworkID(), root,
                {root.op(sponsorFutureReserves(sponsoredAcc)),
                 sponsoredAcc.op(opCreate),
                 sponsoredAcc.op(confirmAndClearSponsor())},
                {sponsoredAcc.getSecretKey()});
            auto tx2 = transactionFrameFromOps(app.getNetworkID(), root,
                                               {sponsoredAcc.op(opModify1)},
                                               {sponsoredAcc.getSecretKey()});
            auto tx3 = transactionFrameFromOps(
                app.getNetworkID(), root,
                {a2.op(sponsorFutureReserves(sponsoredAcc)),
                 sponsoredAcc.op(opModify2),
                 sponsoredAcc.op(confirmAndClearSponsor())},
                {a2.getSecretKey(), sponsoredAcc.getSecretKey()});
            auto tx4 = transactionFrameFromOps(app.getNetworkID(), root,
                                               {sponsoredAcc.op(opRemove)},
                                               {sponsoredAcc.getSecretKey()});

            auto check = [&](AbstractLedgerTxn& l) {
                switch (uso.type())
                {
                case REVOKE_SPONSORSHIP_LEDGER_ENTRY:
                    checkSponsorship(l, uso.ledgerKey(), 1,
                                     &root.getPublicKey());
                    break;
                case REVOKE_SPONSORSHIP_SIGNER:
                    checkSponsorship(l, uso.signer().accountID,
                                     uso.signer().signerKey, 2,
                                     &root.getPublicKey());
                    break;
                default:
                    REQUIRE(false);
                }
            };

            {
                LedgerTxn ltx(app.getLedgerTxnRoot());
                TransactionMeta txm(2);
                REQUIRE(tx->checkValid(ltx, 0, 0, 0));
                REQUIRE(tx->apply(app, ltx, txm));

                check(ltx);
                checkSponsorship(ltx, sponsoredAcc, 0, nullptr, nse + 1, 2, 0,
                                 1);
                checkSponsorship(ltx, root, 0, nullptr, 0, 2, 1, 0);
                ltx.commit();
            }

            // Modify sponsored entry
            {
                LedgerTxn ltx2(app.getLedgerTxnRoot());
                TransactionMeta txm2(2);
                REQUIRE(tx2->checkValid(ltx2, 0, 0, 0));
                REQUIRE(tx2->apply(app, ltx2, txm2));

                check(ltx2);
                checkSponsorship(ltx2, sponsoredAcc, 0, nullptr, nse + 1, 2, 0,
                                 1);
                checkSponsorship(ltx2, root, 0, nullptr, 0, 2, 1, 0);
                ltx2.commit();
            }

            // Modify sponsored entry while sponsored
            {
                LedgerTxn ltx3(app.getLedgerTxnRoot());
                TransactionMeta txm3(2);
                REQUIRE(tx3->checkValid(ltx3, 0, 0, 0));
                REQUIRE(tx3->apply(app, ltx3, txm3));

                check(ltx3);
                checkSponsorship(ltx3, sponsoredAcc, 0, nullptr, nse + 1, 2, 0,
                                 1);
                checkSponsorship(ltx3, root, 0, nullptr, 0, 2, 1, 0);
                checkSponsorship(ltx3, a2, 0, nullptr, 0, 0, 0, 0);
                ltx3.commit();
            }

            // Remove sponsored entry
            {
                LedgerTxn ltx4(app.getLedgerTxnRoot());
                TransactionMeta txm4(2);
                REQUIRE(tx4->checkValid(ltx4, 0, 0, 0));
                REQUIRE(tx4->apply(app, ltx4, txm4));

                if (uso.type() == REVOKE_SPONSORSHIP_LEDGER_ENTRY)
                {
                    REQUIRE(!ltx4.load(uso.ledgerKey()));
                }
                checkSponsorship(ltx4, sponsoredAcc, 0, nullptr, nse, 2, 0, 0);
                checkSponsorship(ltx4, root, 0, nullptr, 0, 2, 0, 0);
                ltx4.commit();
            }
        });
    }
}

void
createModifyAndRemoveSponsoredEntry(Application& app, TestAccount& sponsoredAcc,
                                    Operation const& opCreate,
                                    Operation const& opModify1,
                                    Operation const& opModify2,
                                    Operation const& opRemove,
                                    LedgerKey const& lk)
{
    RevokeSponsorshipOp uso(REVOKE_SPONSORSHIP_LEDGER_ENTRY);
    uso.ledgerKey() = lk;
    createModifyAndRemoveSponsoredEntry(app, sponsoredAcc, opCreate, opModify1,
                                        opModify2, opRemove, uso);
}

void
createModifyAndRemoveSponsoredEntry(Application& app, TestAccount& sponsoredAcc,
                                    Operation const& opCreate,
                                    Operation const& opModify1,
                                    Operation const& opModify2,
                                    Operation const& opRemove,
                                    SignerKey const& signerKey)
{
    RevokeSponsorshipOp uso(REVOKE_SPONSORSHIP_SIGNER);
    uso.signer().accountID = sponsoredAcc;
    uso.signer().signerKey = signerKey;
    createModifyAndRemoveSponsoredEntry(app, sponsoredAcc, opCreate, opModify1,
                                        opModify2, opRemove, uso);
}

void
tooManySponsoring(Application& app, TestAccount& sponsoredAcc,
                  Operation const& successfulOp, Operation const& failOp)
{
    tooManySponsoring(app, sponsoredAcc, sponsoredAcc, successfulOp, failOp);
}
void
tooManySponsoring(Application& app, TestAccount& successfulOpAcc,
                  TestAccount& failOpAcc, Operation const& successfulOp,
                  Operation const& failOp)
{
    auto root = TestAccount::createRoot(app);
    SECTION("too many sponsoring")
    {
        auto sponsoringAcc =
            root.create("TooManySponsoringAcc",
                        app.getLedgerManager().getLastMinBalance(UINT32_MAX));
        {
            LedgerTxn ltx(app.getLedgerTxnRoot());
            auto acc = stellar::loadAccount(ltx, sponsoringAcc.getPublicKey());
            auto& le = acc.current();
            auto& ae = le.data.account();
            ae.ext.v(1);
            ae.ext.v1().ext.v(2);

            uint32_t offset = 1;
            // we want to be able to do one successful op before the fail op
            if (successfulOp.body.type() == REVOKE_SPONSORSHIP &&
                successfulOp.body.revokeSponsorshipOp().type() ==
                    REVOKE_SPONSORSHIP_LEDGER_ENTRY &&
                successfulOp.body.revokeSponsorshipOp().ledgerKey().type() ==
                    ACCOUNT)
            {
                ++offset;
            }
            else if (successfulOp.body.type() == CREATE_ACCOUNT)
            {
                ++offset;
            }

            ae.ext.v1().ext.v2().numSponsoring = UINT32_MAX - offset;
            ltx.commit();
        }

        // add enough balance so we don't hit low reserve
        root.pay(sponsoringAcc, app.getLedgerManager().getLastMinBalance(4));
        {
            auto tx1 = transactionFrameFromOps(
                app.getNetworkID(), successfulOpAcc,
                {sponsoringAcc.op(sponsorFutureReserves(successfulOpAcc)),
                 successfulOp, successfulOpAcc.op(confirmAndClearSponsor())},
                {sponsoringAcc});

            LedgerTxn ltx(app.getLedgerTxnRoot());
            TransactionMeta txm1(2);
            REQUIRE(tx1->checkValid(ltx, 0, 0, 0));
            REQUIRE(tx1->apply(app, ltx, txm1));
            ltx.commit();
        }

        {
            auto tx2 = transactionFrameFromOps(
                app.getNetworkID(), failOpAcc,
                {sponsoringAcc.op(sponsorFutureReserves(failOpAcc)), failOp,
                 failOpAcc.op(confirmAndClearSponsor())},
                {sponsoringAcc});

            LedgerTxn ltx(app.getLedgerTxnRoot());
            TransactionMeta txm2(2);
            REQUIRE(tx2->checkValid(ltx, 0, 0, 0));
            REQUIRE(!tx2->apply(app, ltx, txm2));
            REQUIRE(tx2->getResult().result.results()[1].code() ==
                    opTOO_MANY_SPONSORING);
            ltx.commit();
        }
    }
}
}
