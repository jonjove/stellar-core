// Copyright 2020 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#pragma once

#include "transactions/OperationFrame.h"

namespace stellar
{
enum class SponsorshipResult;

class UpdateSponsorshipOpFrame : public OperationFrame
{
    ThresholdLevel getThresholdLevel() const override;
    bool isVersionSupported(uint32_t protocolVersion) const override;

    UpdateSponsorshipResult&
    innerResult()
    {
        return mResult.tr().updateSponsorshipResult();
    }
    UpdateSponsorshipOp const& mUpdateSponsorshipOp;

    bool processSponsorshipResult(SponsorshipResult sr);

    bool updateLedgerEntrySponsorship(AbstractLedgerTxn& ltx);
    bool updateSignerSponsorship(AbstractLedgerTxn& ltx);

  public:
    UpdateSponsorshipOpFrame(Operation const& op, OperationResult& res,
                             TransactionFrame& parentTx);

    bool doApply(AbstractLedgerTxn& ltx) override;
    bool doCheckValid(uint32_t ledgerVersion) override;

    static UpdateSponsorshipResultCode
    getInnerCode(OperationResult const& res)
    {
        return res.tr().updateSponsorshipResult().code();
    }
};
}
