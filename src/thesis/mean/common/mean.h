#pragma once

#include "base/party.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/run_time_statistics.h"
#include "utility/typedefs.h"

struct Attributes;
struct StatisticsContext;

encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer &party,
                                                     std::size_t input_size,
                                                     encrypto::motion::MpcProtocol protocol);
