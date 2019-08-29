// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "transactions/TransactionFrameBase.h"
#include "transactions/FeeBumpTransactionFrame.h"
#include "transactions/TransactionFrame.h"

namespace stellar
{

bool
signatureCompare(DecoratedSignature const& lhs, DecoratedSignature const& rhs)
{
    return lhs.hint < rhs.hint ||
           (lhs.hint == rhs.hint && lhs.signature < rhs.signature);
}

TransactionFrameBasePtr
TransactionFrameBase::makeTransactionFromWire(Hash const& networkID,
                                              TransactionEnvelope const& env)
{
    switch (env.type())
    {
    case ENVELOPE_TYPE_TX_V0:
        return std::make_shared<TransactionFrame>(networkID, env, true);
    case ENVELOPE_TYPE_FEE_BUMP:
        return std::make_shared<FeeBumpTransactionFrame>(networkID, env);
    default:
        throw std::runtime_error("Unexpected envelope type");
    }
}
}
