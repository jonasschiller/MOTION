

#include "logreg.h"

#include "algorithm/algorithm_description.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer &party,
                                                     std::size_t iterations,
                                                     encrypto::motion::MpcProtocol protocol)
{
  std::vector<encrypto::motion::BitVector<>> tmp(352,
                                                 encrypto::motion::BitVector<>(300));
  std::vector<encrypto::motion::BitVector<>> weights(160, encrypto::motion::BitVector<>(300));
  encrypto::motion::ShareWrapper data{
      protocol == encrypto::motion::MpcProtocol::kBooleanGmw
          ? party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(tmp, 0)
          : party->In<encrypto::motion::MpcProtocol::kBmr>(tmp, 0)};
  encrypto::motion::ShareWrapper weights_shared{
      protocol == encrypto::motion::MpcProtocol::kBooleanGmw ? party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(weights, 0)
                                                             : party->In<encrypto::motion::MpcProtocol::kBmr>(weights, 0)};

  const auto kPathToAlgorithm{std::string(encrypto::motion::kRootDir) +
                              "/circuits/benchmarks/logreg.bristol"};
  const auto logreg_algorithm{encrypto::motion::AlgorithmDescription::FromBristol(kPathToAlgorithm)};
  encrypto::motion::ShareWrapper input;
  for (int i = 0; i < iterations; i++)
  {
    std::vector<encrypto::motion::ShareWrapper> keep_concat;
    keep_concat.push_back(data);
    keep_concat.push_back(weights_shared);
    input = encrypto::motion::ShareWrapper::Concatenate(keep_concat);
    const auto result{input.Evaluate(logreg_algorithm)};
    weights_shared = result;
    for (int j = 0; j < 5; j++)
    {
      std::vector<std::vector<mo::ShareWrapper>> keep_concat(300);
      for (int k = 0; k < 32; k++)
      {
        for (int t = 0; t < 300; t++)
        {
          keep_concat[t].push_back(result[j * 32 + k][t]);
        }
      }
    }
  }
  party->Run();
  party->Finish();
  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}
