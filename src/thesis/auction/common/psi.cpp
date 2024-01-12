#include "psi.h"

#include <cstddef>
#include <fstream>
#include <limits>
#include <span>
#include <vector>
#include "algorithm/algorithm_description.h"
#include "base/backend.h"
#include "base/register.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_wire.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "secure_type/secure_unsigned_integer.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/bit_vector.h"
#include "utility/block.h"
#include "utility/config.h"

namespace mo = encrypto::motion;
/*
Stores the input attributes of party_0 and party_1.
*/
struct Attributes {
  std::vector<std::uint32_t> cleartext_input;  // values for party_0 and categories for party_1.
  std::vector<mo::ShareWrapper> ids;
} party_0, party_1;

/**
 * Stores all the inputs needed for StatisticCircuit().
 */
struct PsiContext {
  Attributes party_0, party_1;
  mo::ShareWrapper full_zero, zero, one;
  std::vector<mo::SecureUnsignedInteger> results;
};

mo::RunTimeStatistics EvaluateProtocol(mo::PartyPointer& party, const std::string& input_file_path,
                                       mo::MpcProtocol protocol) {
  std::uint32_t zero_help = 0;
  std::uint32_t one_help = 1;

  std::vector<mo::SecureUnsignedInteger> storage(12);
  for (std::uint32_t i = 0; i < storage.size(); i++) {
    storage[i] = party->In<mo::MpcProtocol::kArithmeticGmw>(zero_help, 0);
  }

  auto party_id = party->GetConfiguration()->GetMyId();

  const auto [party_0_temp, party_1_temp] = GetFileInput(party_id, input_file_path);
  party_0.cleartext_input = party_0_temp;
  party_1.cleartext_input = party_1_temp;

  for (std::size_t i = 0; i < party_0.cleartext_input.size(); i++) {
    party_0.ids.push_back(
        party->In<mo::MpcProtocol::kArithmeticGmw>(party_0.cleartext_input[i], 0));
    party_1.ids.push_back(
        party->In<mo::MpcProtocol::kArithmeticGmw>(party_1.cleartext_input[i], 1));
  }

  mo::ShareWrapper full_zero =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::BitVector<>(1, false), 0);
  mo::ShareWrapper zero = party->In<mo::MpcProtocol::kArithmeticGmw>(zero_help, 0);
  mo::ShareWrapper one = party->In<mo::MpcProtocol::kArithmeticGmw>(one_help, 0);

  PsiContext context{party_0, party_1, full_zero, zero, one, storage};
  std::vector<mo::SecureUnsignedInteger> output = CreatePsiCircuit(context);
  // Constructs an output gate for each bin.
  for (std::size_t i = 0; i < output.size(); i++) output[i] = output[i].Out();
  party->Run();
  // Converts the outputs to integers.
  std::vector<std::uint32_t> result;
  for (auto each_output : output) result.push_back(each_output.As<std::uint32_t>());

  for (std::size_t i = 0; i < party_0.ids.size(); i++) {
    std::cout << " " << result[i] << "," << std::endl;
  }

  party->Finish();
  const auto& statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}

/**
 * Takes inputs from file in path.
 */
std::tuple<std::vector<std::uint32_t>, std::vector<std::uint32_t>> GetFileInput(
    std::size_t party_id, const std::string& path) {
  std::ifstream infile;
  std::vector<std::uint32_t> party_0, party_1;
  std::uint32_t n;

  infile.open(path);
  if (!infile.is_open()) throw std::runtime_error("Could not open Index file");
  while (infile >> n) {
    if (party_id == 0) {
      party_0.push_back(n);  // Assigns input values to party_0.
      party_1.push_back(n);  // Assigns dummy input to party_1.
    } else {
      party_0.push_back(n);  // Assigns dummy input to party_0..
      party_1.push_back(n);  // Assigns input values to party_1.
    }
  }
  infile.close();
  return {party_0, party_1};
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
 * Constructs the cross tabs of the given data in CrossTabsContext.
 * */
std::vector<mo::SecureUnsignedInteger> CreatePsiCircuit(PsiContext context) {
  auto party_0_id = context.party_0.ids, party_1_id = context.party_1.ids;
  mo::ShareWrapper id_match;
  mo::ShareWrapper keep;
  for (std::size_t i = 0; i < party_0_id.size(); i++) {
    keep = (context.zero > context.zero);
    std::cout << "Start" << std::endl;
    for (std::size_t j = 0; j < party_1_id.size(); j++) {
      id_match =
          (mo::SecureUnsignedInteger(party_0_id[i].Convert<mo::MpcProtocol::kBooleanGmw>()) ==
           mo::SecureUnsignedInteger(party_1_id[j].Convert<mo::MpcProtocol::kBooleanGmw>()));
      keep = (keep | id_match);
    }
    keep = prepare_keep(keep, context.full_zero);
    context.results[i] = mo::SecureUnsignedInteger(keep * party_0_id[i]);
  }

  return context.results;
}
