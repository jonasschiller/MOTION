
#pragma once

#include "base/party.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/run_time_statistics.h"
#include "utility/typedefs.h"

struct Attributes;
struct PsiContext;

encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer &party,
                                                     std::size_t input_size,
                                                     encrypto::motion::MpcProtocol protocol);

void CreatePsiCircuit(PsiContext *context);
encrypto::motion::ShareWrapper prepare_keep(encrypto::motion::ShareWrapper keep,
                                            encrypto::motion::ShareWrapper full_zero);