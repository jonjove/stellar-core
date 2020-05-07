// Copyright 2020 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "ledger/LedgerTxnImpl.h"

namespace stellar
{

void
LedgerTxnRoot::Impl::dropPreauthorizations()
{
    throwIfChild();
    mEntryCache.clear();
    mBestOffersCache.clear();

    std::string coll = mDatabase.getSimpleCollationClause();

    mDatabase.getSession() << "DROP TABLE IF EXISTS preauthorization;";
    mDatabase.getSession() << "CREATE TABLE preauthorization ("
                              "accountid VARCHAR(56) " << coll <<
                              " PRIMARY KEY, "
                              "asset     TEXT " << coll << " NOT NULL, "
                              "flags     INT NOT NULL, "
                              "reserve   BIGINT NOT NULL);";
}

}
