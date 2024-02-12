#pragma once

#include "base/party.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/run_time_statistics.h"
#include "utility/typedefs.h"

struct AuctionContext;

encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer &party, std::size_t input_size,
                                                     encrypto::motion::MpcProtocol protocol);

<<<<<<< Updated upstream
void CreateAuctionCircuit(PsiContext *context);
=======
void CreateAuctionCircuit(AuctionContext *context);
>>>>>>> Stashed changes
encrypto::motion::ShareWrapper prepare_keep(encrypto::motion::ShareWrapper keep,
                                            encrypto::motion::ShareWrapper full_zero);
