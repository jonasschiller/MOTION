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

/**
 * Stores all the inputs needed for StatisticCircuit().
 */
struct PsiContext
{
  std::vector<mo::ShareWrapper> input_1, input_2;
  mo::ShareWrapper full_zero;
  mo::SecureUnsignedInteger zero;
  std::vector<mo::SecureUnsignedInteger> results;
};

mo::RunTimeStatistics EvaluateProtocol(mo::PartyPointer &party, std::size_t input_size,
                                       mo::MpcProtocol protocol)
{
  std::uint32_t zero_help = 0;
  std::uint32_t one_help = 1;

  std::vector<mo::SecureUnsignedInteger> results(input_size);
  for (std::size_t i = 0; i < input_size; i++)
  {
    results[i] = party->In<mo::MpcProtocol::kArithmeticGmw>(0, 0);
  }

  auto party_id = party->GetConfiguration()->GetMyId();

  std::vector<std::uint32_t> party_0(input_size, 1), party_1(input_size, 1);
  std::vector<mo::ShareWrapper> input_0, input_1;

  for (std::size_t i = 0; i < party_0.size(); i++)
  {
    input_0.push_back(
        party->In<mo::MpcProtocol::kArithmeticGmw>(party_0[i], 0));
    input_1.push_back(
        party->In<mo::MpcProtocol::kArithmeticGmw>(party_1[i], 0));
  }

  mo::ShareWrapper full_zero =
      party->In<mo::MpcProtocol::kBooleanGmw>(mo::BitVector<>(1, false), 0);
  mo::SecureUnsignedInteger zero = party->In<mo::MpcProtocol::kBooleanGmw>(mo::ToInput(zero_help), 0);

  PsiContext context{input_0, input_1, full_zero, zero, results};
  CreatePsiCircuit(&context);
  // Constructs an output gate for each bin.
  for (std::size_t i = 0; i < context.results.size(); i++)
    context.results[i] = context.results[i].Out();
  party->Run();
  // Converts the outputs to integers.
  std::vector<std::uint32_t> result;
  for (auto each_output : context.results)
    result.push_back(each_output.As<std::uint32_t>());

  for (std::size_t i = 0; i < input_size; i++)
  {
    std::cout << " " << result[i] << "," << std::endl;
  }

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

/**
 * Constructs the cross tabs of the given data in CrossTabsContext.
 * */
void CreatePsiCircuit(PsiContext *context)
{
  mo::ShareWrapper id_match;
  mo::ShareWrapper keep;
  for (std::size_t i = 0; i < context->input_1.size(); i++)
  {
    keep = (context->zero > context->zero);
    for (std::size_t j = 0; j < context->input_2.size(); j++)
    {
      id_match =
          (mo::SecureUnsignedInteger(context->input_1[i].Convert<mo::MpcProtocol::kBooleanGmw>()) ==
           mo::SecureUnsignedInteger(context->input_2[j].Convert<mo::MpcProtocol::kBooleanGmw>()));
      keep = (keep | id_match);
    }
    keep = prepare_keep(keep, context->full_zero);
    context->results[i] = mo::SecureUnsignedInteger(keep * context->input_1[i]);
  }
}
