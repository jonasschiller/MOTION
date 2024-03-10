#include "min.h"

#include <cstddef>
#include <fstream>
#include <limits>
#include <span>
#include <vector>
#include "algorithm/algorithm_description.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/bmr/bmr_share.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/config.h"

// Abbreviate Namespace
namespace mo = encrypto::motion;
encrypto::motion::ShareWrapper DummyBooleanGmwShare(encrypto::motion::PartyPointer &party,
                                                    std::size_t number_of_wires,
                                                    std::size_t number_of_simd)
{
  std::vector<encrypto::motion::WirePointer> wires(number_of_wires);
  const encrypto::motion::BitVector<> dummy_input(number_of_simd);

  encrypto::motion::BackendPointer backend{party->GetBackend()};
  encrypto::motion::RegisterPointer register_pointer{backend->GetRegister()};

  for (auto &w : wires)
  {
    w = register_pointer->EmplaceWire<encrypto::motion::proto::boolean_gmw::Wire>(dummy_input,
                                                                                  *backend);
    w->SetOnlineFinished();
  }

  return encrypto::motion::ShareWrapper(
      std::make_shared<encrypto::motion::proto::boolean_gmw::Share>(wires));
}
/**
 * Stores all the inputs needed for StatisticCircuit().
 */
struct StatisticsContext
{
  mo::ShareWrapper shared_input;
  mo::ShareWrapper input_size;
  mo::ShareWrapper value;
  mo::ShareWrapper full_zero;
};

/*
 * Runs the protocol and returns the runtime statistics.
 * First reads in the files and then calculates sum, mean, min and max
 */
mo::RunTimeStatistics EvaluateProtocol(mo::PartyPointer &party, std::size_t input_size,
                                       mo::MpcProtocol protocol)
{
  // Get respective party id
  auto party_id = party->GetConfiguration()->GetMyId();
  // Load the dummy input
  mo::ShareWrapper shared_input;
  // insert the Input
  shared_input = DummyBooleanGmwShare(party, 32, input_size);
  // Create the context for the circuit
  uint32_t zero = 0;
  mo::ShareWrapper size = party->In<mo::MpcProtocol::kBooleanGmw>(
      mo::ToInput(input_size), 1);
  mo::ShareWrapper value = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 1);
  mo::ShareWrapper full_zero =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::BitVector<>(1, false), 0);

  StatisticsContext context{shared_input, size, value, full_zero};
  // Create the circuit
  CreateMinMaxCircuit(&context, true);
  auto min_value = context.value.Out();
  party->Run();
  party->Finish();

  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}

/**
 * Transform the boolean value in keep into an arithmetic share.
 */
mo::ShareWrapper prepare_keep(mo::ShareWrapper keep, mo::ShareWrapper full_zero)
{
  std::vector<mo::ShareWrapper> keep_concat;
  keep_concat.push_back(keep);
  for (std::size_t s = 0; s < 31; s++)
    keep_concat.push_back(full_zero);
  keep = mo::ShareWrapper::Concatenate(keep_concat);
  keep = keep.Convert<mo::MpcProtocol::kArithmeticGmw>();
  return keep;
}

void CreateMinMaxCircuit(StatisticsContext *context, bool min)
{
  auto values = context->shared_input.Unsimdify();

  mo::ShareWrapper ge, le, eq;

  context->value = values[0];
  for (std::size_t i = 0; i < values.size(); i++)
  {
    ge = (mo::SecureUnsignedInteger((values[i])) >
          mo::SecureUnsignedInteger(context->value));
    le = (mo::SecureUnsignedInteger(context->value) > mo::SecureUnsignedInteger(values[i]));
    eq = (context->value == (values[i]));
    // Transform into arithmetic uint 32 mask
    ge = prepare_keep(ge, context->full_zero);
    le = prepare_keep(le, context->full_zero);
    eq = prepare_keep(eq, context->full_zero);
    // Calculate the new max value
    if (min == false)
    {
      context->value = le * context->value.Convert<mo::MpcProtocol::kArithmeticGmw>() +
                       ge * values[i].Convert<mo::MpcProtocol::kArithmeticGmw>().Get() + eq * values[i].Convert<mo::MpcProtocol::kArithmeticGmw>().Get();
    }
    else
    {
      context->value = ge * context->value.Convert<mo::MpcProtocol::kArithmeticGmw>() +
                       le * values[i].Convert<mo::MpcProtocol::kArithmeticGmw>().Get() + eq * values[i].Convert<mo::MpcProtocol::kArithmeticGmw>().Get();
    }
    context->value = context->value.Convert<mo::MpcProtocol::kBooleanGmw>();
  }
}
