// Copyright 2019 Stellar Development Foundation and contributors. Licensed
// under the Apache License, Version 2.0. See the COPYING file at the root
// of this distribution or at http://www.apache.org/licenses/LICENSE-2.0

#include "catchup/ApplyBufferedLedgersWork.h"
#include "bucket/BucketList.h"
#include "bucket/BucketManager.h"
#include "catchup/ApplyLedgerWork.h"
#include "ledger/LedgerManager.h"
#include "main/Application.h"

#include <util/format.h>

namespace stellar
{
ApplyBufferedLedgersWork::ApplyBufferedLedgersWork(Application& app)
    : BasicWork(app, "apply-buffered-ledgers", BasicWork::RETRY_NEVER)
{
}

void
ApplyBufferedLedgersWork::onReset()
{
    mConditionalWork.reset();
}

BasicWork::State
ApplyBufferedLedgersWork::onRun()
{
    if (mConditionalWork)
    {
        mConditionalWork->crankWork();
        if (mConditionalWork->getState() != State::WORK_SUCCESS)
        {
            return mConditionalWork->getState();
        }
    }

    auto& cm = mApp.getCatchupManager();
    if (!cm.hasBufferedLedger())
    {
        return State::WORK_SUCCESS;
    }

    LedgerCloseData lcd = cm.popBufferedLedger();

    CLOG(INFO, "History") << "Scheduling buffered ledger-close: "
                          << "[seq=" << lcd.getLedgerSeq() << ", prev="
                          << hexAbbrev(lcd.getTxSet()->previousLedgerHash())
                          << ", txs=" << lcd.getTxSet()->sizeTx()
                          << ", ops=" << lcd.getTxSet()->sizeOp() << ", sv: "
                          << stellarValueToString(mApp.getConfig(),
                                                  lcd.getValue())
                          << "]";

    auto applyLedger = std::make_shared<ApplyLedgerWork>(mApp, lcd);

    auto predicate = [&]() {
        auto& bl = mApp.getBucketManager().getBucketList();
        bl.resolveAnyReadyFutures();
        return bl.futuresAllResolved(bl.getMaxMergeLevel(
            mApp.getLedgerManager().getLastClosedLedgerNum() + 1));
    };

    mConditionalWork = std::make_shared<ConditionalWork>(
        mApp,
        fmt::format("apply-buffered-ledger-conditional ledger({})",
                    lcd.getLedgerSeq()),
        predicate, applyLedger, std::chrono::milliseconds(500));

    mConditionalWork->startWork(wakeSelfUpCallback());

    return State::WORK_RUNNING;
}
}