// Copyright 2020 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "ledger/LedgerTxn.h"
#include "lib/catch.hpp"
#include "main/Application.h"
#include "main/Config.h"
#include "test/TestAccount.h"
#include "test/TestExceptions.h"
#include "test/TestMarket.h"
#include "test/TestUtils.h"
#include "test/TxTests.h"
#include "test/test.h"
#include "transactions/SignatureUtils.h"
#include "transactions/TransactionFrameBase.h"
#include "transactions/TransactionUtils.h"
#include "transactions/test/SponsorshipTestUtils.h"

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

static CreateAccountResultCode
getCreateAccountResultCode(TransactionFrameBasePtr& tx, size_t i)
{
    auto const& opRes = tx->getResult().result.results()[i];
    return opRes.tr().createAccountResult().code();
}

TEST_CASE("create account", "[tx][createaccount]")
{
    VirtualClock clock;
    auto app = createTestApplication(clock, getTestConfig());
    app->start();

    // set up world
    auto root = TestAccount::createRoot(*app);

    int64_t const txfee = app->getLedgerManager().getLastTxFee();
    int64_t const minBalance2 =
        app->getLedgerManager().getLastMinBalance(2) + 10 * txfee;

    SECTION("malformed with bad starting balance")
    {
        for_versions({13}, *app, [&] {
            auto key = SecretKey::pseudoRandomForTesting();
            auto tx1 = transactionFrameFromOps(
                app->getNetworkID(), root,
                {root.op(createAccount(key.getPublicKey(), 0))}, {});
            root.loadSequenceNumber();
            auto tx2 = transactionFrameFromOps(
                app->getNetworkID(), root,
                {root.op(createAccount(key.getPublicKey(), 1))}, {});

            LedgerTxn ltx(app->getLedgerTxnRoot());
            REQUIRE(!tx1->checkValid(ltx, 0, 0, 0));
            REQUIRE(getCreateAccountResultCode(tx1, 0) ==
                    CREATE_ACCOUNT_MALFORMED);

            REQUIRE(tx2->checkValid(ltx, 0, 0, 0));
        });

        for_versions_from(14, *app, [&] {
            auto key = SecretKey::pseudoRandomForTesting();
            auto tx1 = transactionFrameFromOps(
                app->getNetworkID(), root,
                {root.op(createAccount(key.getPublicKey(), -1))}, {});
            root.loadSequenceNumber();
            auto tx2 = transactionFrameFromOps(
                app->getNetworkID(), root,
                {root.op(createAccount(key.getPublicKey(), 0))}, {});

            LedgerTxn ltx(app->getLedgerTxnRoot());
            REQUIRE(!tx1->checkValid(ltx, 0, 0, 0));
            REQUIRE(getCreateAccountResultCode(tx1, 0) ==
                    CREATE_ACCOUNT_MALFORMED);

            REQUIRE(tx2->checkValid(ltx, 0, 0, 0));
        });
    }

    SECTION("malformed with destination")
    {
        for_versions({13}, *app, [&] {
            auto tx =
                transactionFrameFromOps(app->getNetworkID(), root,
                                        {root.op(createAccount(root, -1))}, {});

            LedgerTxn ltx(app->getLedgerTxnRoot());
            REQUIRE(!tx->checkValid(ltx, 0, 0, 0));
            REQUIRE(getCreateAccountResultCode(tx, 0) ==
                    CREATE_ACCOUNT_MALFORMED);
        });
    }

    SECTION("Success")
    {
        for_all_versions(*app, [&] {
            auto b1 =
                root.create("B", app->getLedgerManager().getLastMinBalance(0));
            SECTION("Account already exists")
            {
                REQUIRE_THROWS_AS(
                    root.create("B",
                                app->getLedgerManager().getLastMinBalance(0)),
                    ex_CREATE_ACCOUNT_ALREADY_EXIST);
            }
        });
    }

    SECTION("Not enough funds (source)")
    {
        for_all_versions(*app, [&] {
            int64_t gatewayPayment = minBalance2 + 1;
            auto gateway = root.create("gate", gatewayPayment);
            REQUIRE_THROWS_AS(gateway.create("B", gatewayPayment),
                              ex_CREATE_ACCOUNT_UNDERFUNDED);
        });
    }

    SECTION("Amount too small to create account")
    {
        for_all_versions(*app, [&] {
            REQUIRE_THROWS_AS(
                root.create("B",
                            app->getLedgerManager().getLastMinBalance(0) - 1),
                ex_CREATE_ACCOUNT_LOW_RESERVE);
        });
    }

    SECTION("with native selling liabilities")
    {
        for_versions_from(10, *app, [&] {
            auto const minBal0 = app->getLedgerManager().getLastMinBalance(0);
            auto const minBal3 = app->getLedgerManager().getLastMinBalance(3);

            auto const native = makeNativeAsset();
            auto acc1 = root.create("acc1", minBal3 + 2 * txfee + 500);
            auto cur1 = acc1.asset("CUR1");

            TestMarket market(*app);
            market.requireChangesWithOffer({}, [&] {
                return market.addOffer(acc1, {native, cur1, Price{1, 1}, 500});
            });

            REQUIRE_THROWS_AS(acc1.create("acc2", minBal0 + 1),
                              ex_CREATE_ACCOUNT_UNDERFUNDED);
            root.pay(acc1, txfee);
            acc1.create("acc2", minBal0);
        });
    }

    SECTION("with native buying liabilities")
    {
        for_versions_from(10, *app, [&] {
            auto const minBal0 = app->getLedgerManager().getLastMinBalance(0);
            auto const minBal3 = app->getLedgerManager().getLastMinBalance(3);

            auto const native = makeNativeAsset();
            auto acc1 = root.create("acc1", minBal3 + 2 * txfee + 500);
            auto cur1 = acc1.asset("CUR1");

            TestMarket market(*app);
            market.requireChangesWithOffer({}, [&] {
                return market.addOffer(acc1, {cur1, native, Price{1, 1}, 500});
            });

            acc1.create("acc2", minBal0 + 500);
        });
    }

    SECTION("with sponsorship")
    {
        for_versions_from(14, *app, [&] {
            auto key = SecretKey::pseudoRandomForTesting();
            TestAccount a1(*app, key);
            auto tx =
                transactionFrameFromOps(app->getNetworkID(), root,
                                        {root.op(sponsorFutureReserves(a1)),
                                         root.op(createAccount(a1, 0)),
                                         a1.op(confirmAndClearSponsor())},
                                        {key});

            {
                LedgerTxn ltx(app->getLedgerTxnRoot());
                TransactionMeta txm(2);
                REQUIRE(tx->checkValid(ltx, 0, 0, 0));
                REQUIRE(tx->apply(*app, ltx, txm));
                ltx.commit();
            }

            {
                LedgerTxn ltx(app->getLedgerTxnRoot());
                checkSponsorship(ltx, key.getPublicKey(), 1,
                                 &root.getPublicKey(), 0, 2, 0, 2);
                checkSponsorship(ltx, root.getPublicKey(), 0, nullptr, 0, 2, 2,
                                 0);
            }
        });
    }
    SECTION("too many sponsoring")
    {
        auto a2 = root.create(
            "a2", app->getLedgerManager().getLastMinBalance(UINT32_MAX));
        {
            LedgerTxn ltx(app->getLedgerTxnRoot());
            auto acc = stellar::loadAccount(ltx, a2.getPublicKey());
            auto& le = acc.current();
            auto& ae = le.data.account();
            ae.ext.v(1);
            ae.ext.v1().ext.v(2);
            ae.ext.v1().ext.v2().numSponsoring = UINT32_MAX;
            ltx.commit();
        }

        root.pay(a2, app->getLedgerManager().getLastMinBalance(2));

        auto key = getAccount("a1");
        TestAccount a1(*app, key);
        auto tx = transactionFrameFromOps(app->getNetworkID(), a2,
                                          {a2.op(sponsorFutureReserves(a1)),
                                           a2.op(createAccount(a1, 0)),
                                           a1.op(confirmAndClearSponsor())},
                                          {key});

        LedgerTxn ltx(app->getLedgerTxnRoot());
        TransactionMeta txm(2);
        REQUIRE(tx->checkValid(ltx, 0, 0, 0));
        REQUIRE(!tx->apply(*app, ltx, txm));
        REQUIRE(tx->getResult().result.results()[1].code() ==
                opTOO_MANY_SPONSORING);

        ltx.commit();
    }
}
