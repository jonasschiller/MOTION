#include "LeNet.h"

#include "algorithm/algorithm_description.h"
#include "protocols/bmr/bmr_wire.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/config.h"

encrypto::motion::RunTimeStatistics EvaluateProtocol(encrypto::motion::PartyPointer &party,
                                                     std::size_t number_of_simd,
                                                     encrypto::motion::MpcProtocol protocol)
{
  // TODO tests
  std::vector<encrypto::motion::BitVector<>> tmp(640,
                                                 encrypto::motion::BitVector<>(1));
  encrypto::motion::ShareWrapper input{
      protocol == encrypto::motion::MpcProtocol::kBooleanGmw
          ? party->In<encrypto::motion::MpcProtocol::kBooleanGmw>(tmp, 0)
          : party->In<encrypto::motion::MpcProtocol::kBmr>(tmp, 0)};
  const auto kPathToAlgorithm{std::string(encrypto::motion::kRootDir) +
                              "/circuits/LeNet/convL2.bristol"};
  const auto LeNet_algorithm{encrypto::motion::AlgorithmDescription::FromBristol(kPathToAlgorithm)};
  const auto result{input.Evaluate(LeNet_algorithm)};
  encrypto::motion::ShareWrapper output;
  party->Run();
  party->Finish();
  const auto &statistics = party->GetBackend()->GetRunTimeStatistics();
  return statistics.front();
}
