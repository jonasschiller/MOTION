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
/*
Stores the input attributes of party_0 and party_1.
*/
struct Attributes {
  std::vector<std::uint32_t> cleartext_input;  // values for party_0 and categories for party_1.
  std::vector<mo::ShareWrapper> shared_input;
} party_0, party_1;

/**
 * Stores all the inputs needed for StatisticCircuit().
 */
struct StatisticsContext {
  Attributes party_0, party_1;
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
mo::RunTimeStatistics EvaluateProtocol(mo::PartyPointer& party, const std::string& input_file_path,
                                       mo::MpcProtocol protocol) {
  std::vector<std::uint32_t> id;
  // Get respective party id
  auto party_id = party->GetConfiguration()->GetMyId();
  // Load the correct input from file via file_path from command line
  const auto [party_0_temp, party_1_temp, id_temp] = GetFileInput(party_id, input_file_path);
  party_0.cleartext_input = party_0_temp;
  party_1.cleartext_input = party_1_temp;
  id = id_temp;
  // insert the Input for party 0 and party 1
  for (std::size_t i = 0; i < party_0.cleartext_input.size(); i++) {
    party_0.shared_input.push_back(
        party->In<mo::MpcProtocol::kArithmeticGmw>(party_0.cleartext_input[i], 0));
  }
  for (std::size_t i = 0; i < party_1.cleartext_input.size(); i++) {
    party_1.shared_input.push_back(
        party->In<mo::MpcProtocol::kArithmeticGmw>(party_1.cleartext_input[i], 1));
  }
  // Create the context for the circuit
  uint32_t zero = 0;
  mo::ShareWrapper sum = party->In<mo::MpcProtocol::kArithmeticGmw>(zero, 1);
  mo::SecureUnsignedInteger mean = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 1);
  mo::ShareWrapper size = party->In<mo::MpcProtocol::kBooleanGmw>(
      mo::ToInput(party_0.shared_input.size() + party_1.shared_input.size()), 1);
  mo::ShareWrapper value = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 1);
  mo::SecureUnsignedInteger max_value =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 1);
  mo::SecureUnsignedInteger min_value =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero), 1);
  mo::ShareWrapper full_zero =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::BitVector<>(1, false), 0);

  StatisticsContext context{party_0, party_1, sum, mean, size, value, full_zero};
  // Create the circuit

  sum = CreateSumCircuit(context);
  mean = CreateMeanCircuit(context);
  max_value = CreateMinMaxCircuit(context, false);
  min_value = CreateMinMaxCircuit(context, true);
  // Create the output gate
  sum = sum.Out();
  mean = mean.Out();
  max_value = max_value.Out();
  min_value = min_value.Out();
  party->Run();
  std::cout << "Sum " << sum.As<std::uint32_t>() << std::endl;
  std::cout << "Mean " << mean.As<std::uint32_t>() << std::endl;
  std::cout << "Max " << max_value.As<std::uint32_t>() << std::endl;
  std::cout << "Min " << min_value.As<std::uint32_t>() << std::endl;
  party->Finish();

  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}

/**
 * Takes inputs from file in path.
 */
std::tuple<std::vector<std::uint32_t>, std::vector<std::uint32_t>, std::vector<std::uint32_t>>
GetFileInput(std::size_t party_id, const std::string& path) {
  std::ifstream infile;
  std::vector<std::uint32_t> party_0, party_1, id;
  std::uint32_t n;

  infile.open(path);
  if (!infile.is_open()) throw std::runtime_error("Could not open Statistics File");
  std::uint32_t i = 0;
  while (infile >> n) {
    if (party_id == 0) {
      party_0.push_back(n);  // Assigns input values to party_0.
      party_1.push_back(n);  // Assigns dummy input to party_1.
    } else {
      party_0.push_back(n);  // Assigns dummy input to party_0..
      party_1.push_back(n);  // Assigns input values to party_1.
    }
    id.push_back(i);
    i++;
  }
  infile.close();
  return {party_0, party_1, id};
}

/**
 * Transform the boolean value in keep into an arithmetic share.
 */
mo::ShareWrapper prepare_keep(mo::ShareWrapper keep, mo::ShareWrapper full_zero) {
  std::vector<mo::ShareWrapper> keep_concat;
  keep_concat.push_back(keep);
  for (std::size_t s = 0; s < 31; s++) keep_concat.push_back(full_zero);
  keep = mo::ShareWrapper::Concatenate(keep_concat);
  keep = keep.Convert<mo::MpcProtocol::kArithmeticGmw>();
  return keep;
}

/**
 * Calculate the Mean of the values given by the two parties
 * */
mo::SecureUnsignedInteger CreateMeanCircuit(StatisticsContext context) {
  auto party_0_values = context.party_0.shared_input, party_1_values = context.party_1.shared_input;
  context.sum = CreateSumCircuit(context);
  context.mean = mo::SecureUnsignedInteger(context.sum.Convert<mo::MpcProtocol::kBooleanGmw>()) /
                 mo::SecureUnsignedInteger(context.input_size);
  return context.mean;
}

mo::ShareWrapper CreateSumCircuit(StatisticsContext context) {
  auto party_0_values = context.party_0.shared_input, party_1_values = context.party_1.shared_input;
  for (std::size_t i = 0; i < party_0_values.size(); i++) {
    context.sum += party_0_values[i].Get();
  }
  for (std::size_t i = 0; i < party_1_values.size(); i++) {
    context.sum += party_1_values[i].Get();
  }
  return context.sum;
}

mo::ShareWrapper CreateMinMaxCircuit(StatisticsContext context, bool min) {
  auto party_0_values = context.party_0.shared_input, party_1_values = context.party_1.shared_input;

  mo::ShareWrapper ge, le, eq;

  party_0_values.insert(party_0_values.end(), party_1_values.begin(), party_1_values.end());
  if (party_0_values.empty()) {
    throw std::invalid_argument("Vector is empty");
  }
  context.value = party_0_values[0];
  for (std::size_t i = 0; i < party_0_values.size(); i++) {
    context.value = context.value.Convert<mo::MpcProtocol::kBooleanGmw>();
    ge = (mo::SecureUnsignedInteger((party_0_values[i].Convert<mo::MpcProtocol::kBooleanGmw>())) >
          mo::SecureUnsignedInteger(context.value));
    le = (mo::SecureUnsignedInteger(context.value) >
          mo::SecureUnsignedInteger((party_0_values[i].Convert<mo::MpcProtocol::kBooleanGmw>())));
    eq = (context.value == (party_0_values[i].Convert<mo::MpcProtocol::kBooleanGmw>()));

    // Transform into arithmetic uint 32 mask
    ge = prepare_keep(ge, context.full_zero);
    le = prepare_keep(le, context.full_zero);
    eq = prepare_keep(eq, context.full_zero);
    // Calculate the new max value
    if (min == false) {
      context.value = le * context.value.Convert<mo::MpcProtocol::kArithmeticGmw>() +
                      ge * party_0_values[i].Get() + eq * party_0_values[i].Get();
    } else {
      context.value = ge * context.value.Convert<mo::MpcProtocol::kArithmeticGmw>() +
                      le * party_0_values[i].Get() + eq * party_0_values[i].Get();
    }
  }
  return context.value;
}