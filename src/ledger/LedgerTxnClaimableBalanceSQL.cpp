// Copyright 2020 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "crypto/KeyUtils.h"
#include "crypto/SecretKey.h"
#include "ledger/LedgerTxnImpl.h"
#include "util/Decoder.h"
#include "util/types.h"

namespace stellar
{

template <typename T>
std::string
toOpaqueBase64(T const& input)
{
    return decoder::encode_b64(xdr::xdr_to_opaque(input));
}

template <typename T>
void
fromOpaqueBase64(T& res, std::string const& opaqueBase64)
{
    std::vector<uint8_t> opaque;
    decoder::decode_b64(opaqueBase64, opaque);
    xdr::xdr_from_opaque(opaque, res);
}

std::shared_ptr<LedgerEntry const>
LedgerTxnRoot::Impl::loadClaimableBalance(LedgerKey const& key) const
{
    auto balanceID = toOpaqueBase64(key.claimableBalance().balanceID);

    std::string createdByStr, claimantsStr, assetStr;

    LedgerEntry le;
    le.data.type(CLAIMABLE_BALANCE);
    ClaimableBalanceEntry& cbe = le.data.claimableBalance();

    std::string sql =
        "SELECT createdby, claimants, asset, amount, reserve, lastmodified "
        "FROM claimablebalance "
        "WHERE balanceid= :balanceid";
    auto prep = mDatabase.getPreparedStatement(sql);
    auto& st = prep.statement();
    st.exchange(soci::into(createdByStr));
    st.exchange(soci::into(claimantsStr));
    st.exchange(soci::into(assetStr));
    st.exchange(soci::into(cbe.amount));
    st.exchange(soci::into(cbe.reserve));
    st.exchange(soci::into(le.lastModifiedLedgerSeq));
    st.exchange(soci::use(balanceID));
    st.define_and_bind();
    st.execute(true);
    if (!st.got_data())
    {
        return nullptr;
    }

    cbe.balanceID = key.claimableBalance().balanceID;
    cbe.createdBy = KeyUtils::fromStrKey<PublicKey>(createdByStr);
    fromOpaqueBase64(cbe.claimants, claimantsStr);
    fromOpaqueBase64(cbe.asset, assetStr);

    return std::make_shared<LedgerEntry const>(std::move(le));
}

class BulkLoadClaimableBalanceOperation
    : public DatabaseTypeSpecificOperation<std::vector<LedgerEntry>>
{
    Database& mDb;
    std::vector<std::string> mBalanceIDs;

    std::vector<LedgerEntry>
    executeAndFetch(soci::statement& st)
    {
        std::string balanceIdStr, createdByStr, claimantsStr, assetStr;
        int64_t amount, reserve;
        uint32_t lastModifiedLedgerSeq;

        st.exchange(soci::into(balanceIdStr));
        st.exchange(soci::into(createdByStr));
        st.exchange(soci::into(claimantsStr));
        st.exchange(soci::into(assetStr));
        st.exchange(soci::into(amount));
        st.exchange(soci::into(reserve));
        st.exchange(soci::into(lastModifiedLedgerSeq));
        st.define_and_bind();
        {
            auto timer = mDb.getSelectTimer("claimablebalance");
            st.execute(true);
        }

        std::vector<LedgerEntry> res;
        while (st.got_data())
        {
            res.emplace_back();
            auto& le = res.back();
            le.data.type(CLAIMABLE_BALANCE);
            auto& cbe = le.data.claimableBalance();

            fromOpaqueBase64(cbe.balanceID, balanceIdStr);
            cbe.createdBy = KeyUtils::fromStrKey<PublicKey>(createdByStr);
            fromOpaqueBase64(cbe.claimants, claimantsStr);
            fromOpaqueBase64(cbe.asset, assetStr);
            cbe.amount = amount;
            cbe.reserve = reserve;
            le.lastModifiedLedgerSeq = lastModifiedLedgerSeq;

            st.fetch();
        }
        return res;
    }

  public:
    BulkLoadClaimableBalanceOperation(Database& db,
                                      std::unordered_set<LedgerKey> const& keys)
        : mDb(db)
    {
        mBalanceIDs.reserve(keys.size());
        for (auto const& k : keys)
        {
            assert(k.type() == CLAIMABLE_BALANCE);
            mBalanceIDs.emplace_back(
                toOpaqueBase64(k.claimableBalance().balanceID));
        }
    }

    std::vector<LedgerEntry>
    doSqliteSpecificOperation(soci::sqlite3_session_backend* sq) override
    {
        std::vector<char const*> cstrBalanceIDs;
        cstrBalanceIDs.reserve(mBalanceIDs.size());
        for (size_t i = 0; i < mBalanceIDs.size(); ++i)
        {
            cstrBalanceIDs.emplace_back(mBalanceIDs[i].c_str());
        }

        std::string sql =
            "WITH r AS (SELECT value FROM carray(?, ?, 'char*')) "
            "SELECT balanceid, createdby, claimants, asset, amount, reserve "
            "FROM claimablebalance "
            "WHERE balanceid IN r";

        auto prep = mDb.getPreparedStatement(sql);
        auto be = prep.statement().get_backend();
        if (be == nullptr)
        {
            throw std::runtime_error("no sql backend");
        }
        auto sqliteStatement =
            dynamic_cast<soci::sqlite3_statement_backend*>(be);
        auto st = sqliteStatement->stmt_;

        sqlite3_reset(st);
        sqlite3_bind_pointer(st, 1, cstrBalanceIDs.data(), "carray", 0);
        sqlite3_bind_int(st, 2, static_cast<int>(cstrBalanceIDs.size()));
        return executeAndFetch(prep.statement());
    }

#ifdef USE_POSTGRES
    std::vector<LedgerEntry>
    doPostgresSpecificOperation(soci::postgresql_session_backend* pg) override
    {
        std::string strBalanceIDs;
        marshalToPGArray(pg->conn_, strBalanceIDs, mBalanceIDs);

        std::string sql =
            "WITH r AS (SELECT unnest(:v1::TEXT[])) "
            "SELECT balanceid, createdby, claimants, asset, amount, reserve "
            "FROM claimablebalance "
            "WHERE balanceid IN r";

        auto prep = mDb.getPreparedStatement(sql);
        auto& st = prep.statement();
        st.exchange(soci::use(strBalanceIDs));
        return executeAndFetch(st);
    }
#endif
};

std::unordered_map<LedgerKey, std::shared_ptr<LedgerEntry const>>
LedgerTxnRoot::Impl::bulkLoadClaimableBalance(
    std::unordered_set<LedgerKey> const& keys) const
{
    if (!keys.empty())
    {
        BulkLoadClaimableBalanceOperation op(mDatabase, keys);
        return populateLoadedEntries(
            keys, mDatabase.doDatabaseTypeSpecificOperation(op));
    }
    else
    {
        return {};
    }
}

class BulkDeleteClaimableBalanceOperation
    : public DatabaseTypeSpecificOperation<void>
{
    Database& mDb;
    LedgerTxnConsistency mCons;
    std::vector<std::string> mBalanceIDs;

  public:
    BulkDeleteClaimableBalanceOperation(
        Database& db, LedgerTxnConsistency cons,
        std::vector<EntryIterator> const& entries)
        : mDb(db), mCons(cons)
    {
        mBalanceIDs.reserve(entries.size());
        for (auto const& e : entries)
        {
            assert(!e.entryExists());
            assert(e.key().type() == CLAIMABLE_BALANCE);
            mBalanceIDs.emplace_back(
                toOpaqueBase64(e.key().claimableBalance().balanceID));
        }
    }

    void
    doSociGenericOperation()
    {
        std::string sql = "DELETE FROM claimablebalance WHERE balanceid = :id";
        auto prep = mDb.getPreparedStatement(sql);
        auto& st = prep.statement();
        st.exchange(soci::use(mBalanceIDs));
        st.define_and_bind();
        {
            auto timer = mDb.getDeleteTimer("claimablebalance");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) != mBalanceIDs.size() &&
            mCons == LedgerTxnConsistency::EXACT)
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }

    void
    doSqliteSpecificOperation(soci::sqlite3_session_backend* sq) override
    {
        doSociGenericOperation();
    }

#ifdef USE_POSTGRES
    void
    doPostgresSpecificOperation(soci::postgresql_session_backend* pg) override
    {
        std::string strBalanceIDs;
        marshalToPGArray(pg->conn_, strBalanceIDs, mBalanceIDs);

        std::string sql = "WITH r AS (SELECT unnest(:v1::TEXT[])) "
                          "DELETE FROM claimablebalance"
                          "WHERE balanceid IN r";

        auto prep = mDb.getPreparedStatement(sql);
        auto& st = prep.statement();
        st.exchange(soci::use(strBalanceIDs));
        st.define_and_bind();
        {
            auto timer = mDb.getDeleteTimer("claimablebalance");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) != mBalanceIDs.size() &&
            mCons == LedgerTxnConsistency::EXACT)
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }
#endif
};

void
LedgerTxnRoot::Impl::bulkDeleteClaimableBalance(
    std::vector<EntryIterator> const& entries, LedgerTxnConsistency cons)
{
    BulkDeleteClaimableBalanceOperation op(mDatabase, cons, entries);
    mDatabase.doDatabaseTypeSpecificOperation(op);
}

class BulkUpsertClaimableBalanceOperation
    : public DatabaseTypeSpecificOperation<void>
{
    Database& mDb;
    std::vector<std::string> mBalanceIDs;
    std::vector<std::string> mCreatedBys;
    std::vector<std::string> mClaimants;
    std::vector<std::string> mAssets;
    std::vector<int64_t> mAmounts;
    std::vector<int64_t> mReserves;
    std::vector<int32_t> mLastModifieds;

    void
    accumulateEntry(LedgerEntry const& entry)
    {
        assert(entry.data.type() == CLAIMABLE_BALANCE);
        auto const& cbe = entry.data.claimableBalance();
        mBalanceIDs.emplace_back(toOpaqueBase64(cbe.balanceID));
        mCreatedBys.emplace_back(KeyUtils::toStrKey(cbe.createdBy));
        mClaimants.emplace_back(toOpaqueBase64(cbe.claimants));
        mAssets.emplace_back(toOpaqueBase64(cbe.asset));
        mAmounts.emplace_back(cbe.amount);
        mReserves.emplace_back(cbe.reserve);
        mLastModifieds.emplace_back(
            unsignedToSigned(entry.lastModifiedLedgerSeq));
    }

  public:
    BulkUpsertClaimableBalanceOperation(
        Database& Db, std::vector<EntryIterator> const& entryIter)
        : mDb(Db)
    {
        for (auto const& e : entryIter)
        {
            assert(e.entryExists());
            accumulateEntry(e.entry());
        }
    }

    void
    doSociGenericOperation()
    {
        std::string sql =
            "INSERT INTO claimablebalance "
            "(balanceid, createdby, claimant, asset, amount, reserve, "
            "lastmodified) "
            "VALUES "
            "(:id, :v1, :v2, :v3, :v4, :v5, :v6) "
            "ON CONFLICT balanceid DO UPDATE SET "
            "balanceid = excluded.balanceid, createdby = excluded.createdby, "
            "claimant = excluded.claimant, asset = excluded.asset, "
            "amount = excluded.amount, reserve = excluded.reserve, "
            "lastmodified = excluded.lastmodified";

        auto prep = mDb.getPreparedStatement(sql);
        soci::statement& st = prep.statement();
        st.exchange(soci::use(mBalanceIDs));
        st.exchange(soci::use(mCreatedBys));
        st.exchange(soci::use(mClaimants));
        st.exchange(soci::use(mAssets));
        st.exchange(soci::use(mAmounts));
        st.exchange(soci::use(mReserves));
        st.exchange(soci::use(mLastModifieds));
        st.define_and_bind();
        {
            auto timer = mDb.getUpsertTimer("claimablebalance");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) != mBalanceIDs.size())
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }

    void
    doSqliteSpecificOperation(soci::sqlite3_session_backend* sq) override
    {
        doSociGenericOperation();
    }

#ifdef USE_POSTGRES
    void
    doPostgresSpecificOperation(soci::postgresql_session_backend* pg) override
    {
        std::string strBalanceIDs, strCreatedBys, strClaimants, strAssets,
            strAmounts, strReserves, strLastModifieds;

        PGconn* conn = pg->conn_;
        marshalToPGArray(conn, strBalanceIDs, mBalanceIDs);
        marshalToPGArray(conn, strCreatedBys, mCreatedBys);
        marshalToPGArray(conn, strClaimants, mClaimants);
        marshalToPGArray(conn, strAssets, mAssets);
        marshalToPGArray(conn, strAmounts, mAmounts);
        marshalToPGArray(conn, strReserves, mReserves);
        marshalToPGArray(conn, strLastModifieds, mLastModifieds);

        std::string sql =
            "WITH r AS "
            "(SELECT unnest(:ids::TEXT[]), unnest(:v1::TEXT[]), "
            "unnest(:v2::TEXT[]), unnest(:v3::TEXT[]), unnest(:v4::TEXT[]), "
            "unnest(:v5::BIGINT[]), unnest(:v6::BIGINT[]), unnest(:v7::INT[]))"
            "INSERT INTO claimablebalance "
            "(balanceid, createdby, claimant, asset, amount, reserve, "
            "lastmodified) "
            "SELECT * FROM r "
            "ON CONFLICT balanceid DO UPDATE SET "
            "balanceid = excluded.balanceid, createdby = excluded.createdby, "
            "claimant = excluded.claimant, asset = excluded.asset, "
            "amount = excluded.amount, reserve = excluded.reserve, "
            "lastmodified = excluded.lastmodified";

        auto prep = mDb.getPreparedStatement(sql);
        soci::statement& st = prep.statement();
        st.exchange(soci::use(strBalanceIDs));
        st.exchange(soci::use(strCreatedBys));
        st.exchange(soci::use(strClaimants));
        st.exchange(soci::use(strAssets));
        st.exchange(soci::use(strAmounts));
        st.exchange(soci::use(strReserves));
        st.exchange(soci::use(strLastModifieds));
        st.define_and_bind();
        {
            auto timer = mDb.getUpsertTimer("claimablebalance");
            st.execute(true);
        }
        if (static_cast<size_t>(st.get_affected_rows()) != mBalanceIDs.size())
        {
            throw std::runtime_error("Could not update data in SQL");
        }
    }
#endif
};

void
LedgerTxnRoot::Impl::bulkUpsertClaimableBalance(
    std::vector<EntryIterator> const& entries)
{
    BulkUpsertClaimableBalanceOperation op(mDatabase, entries);
    mDatabase.doDatabaseTypeSpecificOperation(op);
}

void
LedgerTxnRoot::Impl::dropClaimableBalances()
{
    throwIfChild();
    mEntryCache.clear();
    mBestOffersCache.clear();

    std::string coll = mDatabase.getSimpleCollationClause();

    mDatabase.getSession() << "DROP TABLE IF EXISTS claimablebalance;";
    mDatabase.getSession() << "CREATE TABLE claimablebalance ("
                           << "balanceid    VARCHAR(56) " << coll
                           << " PRIMARY KEY, "
                           << "createdby    VARCHAR(56) " << coll
                           << " NOT NULL, "
                           << "claimants    TEXT " << coll << " NOT NULL, "
                           << "asset        TEXT " << coll << " NOT NULL, "
                           << "amount       BIGINT NOT NULL, "
                           << "reserve      BIGINT NOT NULL);";
}
}
