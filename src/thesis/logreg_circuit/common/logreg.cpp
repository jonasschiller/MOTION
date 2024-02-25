

#include "logreg.h"

#include "algorithm/algorithm_description.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"
namespace mo = encrypto::motion;
encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer &party,
                                                     std::size_t iterations,
                                                     encrypto::motion::MpcProtocol protocol)
{
  std::vector<encrypto::motion::BitVector<>> tmp(352,
                                                 encrypto::motion::BitVector<>(1));
  std::vector<encrypto::motion::BitVector<>> weights(160, encrypto::motion::BitVector<>(1));
  encrypto::motion::ShareWrapper data{
      protocol == encrypto::motion::MpcProtocol::kBooleanGmw
          ? party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(tmp, 0)
          : party->In<encrypto::motion::MpcProtocol::kBmr>(tmp, 0)};
  encrypto::motion::ShareWrapper weights_shared{
      protocol == encrypto::motion::MpcProtocol::kBooleanGmw ? party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(weights, 0)
                                                             : party->In<encrypto::motion::MpcProtocol::kBmr>(weights, 0)};

  const auto kPathToAlgorithm{std::string(encrypto::motion::kRootDir) +
                              "/circuits/benchmarks/logreg.bristol"};
  const auto kPathToAlgorithm2{std::string(encrypto::motion::kRootDir) +
                               "/circuits/benchmarks/weights.bristol"};
  const auto logreg_algorithm{encrypto::motion::AlgorithmDescription::FromBristol(kPathToAlgorithm)};
  const auto weights_algorithm{encrypto::motion::AlgorithmDescription::FromBristol(kPathToAlgorithm2)};
  encrypto::motion::ShareWrapper input, result;
  std::vector<encrypto::motion::ShareWrapper> keep_concat, output, sum, help;

  keep_concat.push_back(data);
  keep_concat.push_back(weights_shared);
  input = encrypto::motion::ShareWrapper::Concatenate(keep_concat);
  result = input.Evaluate(logreg_algorithm);
  output = result.Unsimdify();
  for (int t = 0; t < 300; t++)
  {
    sum.push_back(output[t]);
  }
  input = mo::ShareWrapper::Concatenate(sum);
  result = input.Evaluate(weights_algorithm);
  sum.clear();
  for (int t = 0; t < 300; t++)
  {
    sum.push_back(result);
  }
  weights_shared = input.Simdify(sum);

  party->Run();
  party->Finish();
  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}
