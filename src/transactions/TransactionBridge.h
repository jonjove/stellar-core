// Copyright 2020 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "xdr/Stellar-transaction.h"
#include <memory>

namespace stellar
{
class TransactionFrame;
typedef std::shared_ptr<TransactionFrame> TransactionFramePtr;

namespace txbridge
{

TransactionEnvelope convertToV1(TransactionEnvelope const& input);

xdr::xvector<DecoratedSignature, 20>& getSignatures(TransactionEnvelope& env);

#ifdef BUILD_TESTS
xdr::xvector<DecoratedSignature, 20>& getSignatures(TransactionFramePtr tx);

void setSeqNum(TransactionFramePtr tx, int64_t seq);

void setFee(TransactionFramePtr tx, uint32_t fee);

void setMinTime(TransactionFramePtr tx, int64_t minTime);

void setMaxTime(TransactionFramePtr tx, int64_t maxTime);
#endif
}
}
