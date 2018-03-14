#pragma once

// Copyright 2015 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "transactions/OperationFrame.h"
#include <memory>

namespace stellar
{
class LedgerState;

class PathPaymentOpFrame : public OperationFrame
{
    PathPaymentResult&
    innerResult()
    {
        return mResult.tr().pathPaymentResult();
    }
    PathPaymentOp const& mPathPayment;

  public:
    PathPaymentOpFrame(Operation const& op, OperationResult& res,
                       TransactionFrame& parentTx);

    bool doApply(Application& app, LedgerState& ls) override;
    bool doCheckValid(Application& app, uint32_t ledgerVersion) override;

    static PathPaymentResultCode
    getInnerCode(OperationResult const& res)
    {
        return res.tr().pathPaymentResult().code();
    }
};
}
