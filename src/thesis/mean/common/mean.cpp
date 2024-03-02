#include "mean.h"

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
  mo::ShareWrapper size = party->In<mo::MpcProtocol::kBooleanGmw>(
      mo::ToInput(input_size), 1);
  auto party_0_values = shared_input;
  for (std::size_t i = 0; i < party_0_values.size(); i++)
  {
    sum += party_0_values[i].Get();
  }
  // Create the circuit
  sum = sum.Convert<mo::MpcProtocol::kBooleanGmw>();
  shared_input.clear();
  shared_input.push_back(sum);
  shared_input.push_back(size);
  mo::ShareWrapper division = mo::ShareWrapper::Concatenate(shared_input);
  const auto kPathToAlgorithm{std::string(encrypto::motion::kRootDir) + "/circuits/fp/division.bristol"};
  const auto division_algorithm{encrypto::motion::AlgorithmDescription::FromBristol(kPathToAlgorithm)};
  const auto mean{input.Evaluate(division_algorithm)};

  mean = mean.Out();
  party->Run();
  party->Finish();

  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}