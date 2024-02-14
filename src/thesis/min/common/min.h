#pragma once

#include "base/party.h"
#include "statistics/run_time_statistics.h"

encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer &party,
                                                     std::size_t input_size,
                                                     encrypto::motion::MpcProtocol protocol);
