#include "statistics.h"

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

/**
 * Stores all the inputs needed for StatisticCircuit().
 */
struct StatisticsContext
{
  std::vector<mo::ShareWrapper> shared_input;
  mo::ShareWrapper sum;
  mo::SecureUnsignedInteger mean;
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
  std::vector<std::uint32_t> input(input_size, 0);
  std::vector<mo::ShareWrapper> shared_input;
  // insert the Input
  for (std::size_t i = 0; i < input.size(); i++)
  {
    shared_input.push_back(
        party->In<mo::MpcProtocol::kArithmeticGmw>(input[i], 0));
  }
  // Create the context for the circuit
  uint32_t zero = 0;
  mo::ShareWrapper sum = party->In<mo::MpcProtocol::kArithmeticGmw>(zero, 1);
  mo::SecureUnsignedInteger mean = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 1);
  mo::ShareWrapper size = party->In<mo::MpcProtocol::kBooleanGmw>(
      mo::ToInput(input_size), 1);
  mo::ShareWrapper value = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 1);
  mo::SecureUnsignedInteger max_value =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 1);
  mo::SecureUnsignedInteger min_value =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 1);
  mo::ShareWrapper full_zero =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::BitVector<>(1, false), 0);

  StatisticsContext context{shared_input, sum, mean, size, value, full_zero};
  // Create the circuit

  CreateSumCircuit(&context);
  // CreateMeanCircuit(&context);
  CreateMinMaxCircuit(&context, false);
  max_value = context.value.Out();
  CreateMinMaxCircuit(&context, true);
  min_value = context.value.Out();
  // Create the output gate
  sum = context.sum.Out();
  mean = context.mean.Out();
  party->Run();
  std::cout << "Sum " << sum.As<std::uint32_t>() << std::endl;
  std::cout << "Mean " << mean.As<std::uint32_t>() << std::endl;
  std::cout << "Max " << max_value.As<std::uint32_t>() << std::endl;
  std::cout << "Min " << min_value.As<std::uint32_t>() << std::endl;
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

***Calculate the Mean of the values given by the two parties
        ** /
    void CreateMeanCircuit(StatisticsContext *context)
{
  auto party_0_values = context->shared_input;
  CreateSumCircuit(context);
  context->mean = mo::SecureUnsignedInteger(context->sum.Convert<mo::MpcProtocol::kBooleanGmw>()) /
                  mo::SecureUnsignedInteger(context->input_size);
}

void CreateSumCircuit(StatisticsContext *context)
{
  auto party_0_values = context->shared_input;
  for (std::size_t i = 0; i < party_0_values.size(); i++)
  {
    context->sum += party_0_values[i].Get();
  }
}

void CreateMinMaxCircuit(StatisticsContext *context, bool min)
{
  auto values = context->shared_input;

  mo::ShareWrapper ge, le, eq;

  context->value = values[0];
  for (std::size_t i = 0; i < values.size(); i++)
  {
    context->value = context->value.Convert<mo::MpcProtocol::kBooleanGmw>();
    ge = (mo::SecureUnsignedInteger((values[i].Convert<mo::MpcProtocol::kBooleanGmw>())) >
          mo::SecureUnsignedInteger(context->value));
    le = (mo::SecureUnsignedInteger(context->value) >
          mo::SecureUnsignedInteger((values[i].Convert<mo::MpcProtocol::kBooleanGmw>())));
    eq = (context->value == (values[i].Convert<mo::MpcProtocol::kBooleanGmw>()));
    // Transform into arithmetic uint 32 mask
    ge = prepare_keep(ge, context->full_zero);
    le = prepare_keep(le, context->full_zero);
    eq = prepare_keep(eq, context->full_zero);
    // Calculate the new max value
    if (min == false)
    {
      context->value = le * context->value.Convert<mo::MpcProtocol::kArithmeticGmw>() +
                       ge * values[i].Get() + eq * values[i].Get();
    }
    else
    {
      context->value = ge * context->value.Convert<mo::MpcProtocol::kArithmeticGmw>() +
                       le * values[i].Get() + eq * values[i].Get();
    }
  }
}
